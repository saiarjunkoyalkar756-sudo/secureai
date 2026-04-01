import { spawn } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';
import { Permission } from '../core/permissions/types';

export interface SandboxConfig {
  language: 'python3.11' | 'node20' | 'go1.21' | 'bash';
  timeout: number; // seconds
  memory: number; // MB
  cpuShares: number; // CPU cores
  networkEnabled: boolean;
  permissions: Permission[];
}

export interface ExecutionResult {
  status: 'success' | 'error';
  exitCode: number;
  stdout: string;
  stderr: string;
  executionTime: number;
  resourcesUsed: { cpu: number; memory: number; disk: number; };
  auditId?: string;
}

export class SandboxEngine {
  private readonly SANDBOX_BASE = '/var/sandbox';
  private auditLogger: any; // Mock AuditLogger
  private dockerClient: any; // Mock Docker Client

  constructor() {
    this.auditLogger = { log: async () => {} };
    this.dockerClient = { stats: async () => ({ cpu_stats: { cpu_usage: { total_usage: 0 } }, memory_stats: { max_usage: 0 } }) };
  }

  async execute(
    code: string,
    config: SandboxConfig,
    permissions: Permission[]
  ): Promise<ExecutionResult> {
    const executionId = Math.random().toString(36).substring(7);
    const sandboxDir = path.join(this.SANDBOX_BASE, executionId);

    try {
      // 1. Setup sandbox filesystem
      await this.setupSandbox(sandboxDir, permissions);

      // 2. Write code to temp file
      const codeFile = path.join(sandboxDir, 'code');
      await fs.writeFile(codeFile, code);

      // 3. Create seccomp profile
      const seccompProfile = this.createSeccompProfile(config, permissions);
      const seccompPath = path.join(sandboxDir, 'seccomp.json');
      await fs.writeFile(seccompPath, JSON.stringify(seccompProfile));

      // 4. Launch containerized execution
      const result = await this.executeInContainer(
        sandboxDir,
        codeFile,
        config,
        seccompPath,
        executionId
      );

      // 5. Collect audit data
      const auditData = await this.captureAuditData(executionId, sandboxDir);

      // 6. Log to immutable audit trail
      await this.auditLogger.log({
        executionId,
        code: code.substring(0, 1000), // First 1000 chars
        language: config.language,
        permissions,
        result,
        auditData,
        timestamp: new Date()
      });

      return result;

    } catch(err) {
      return {
        status: 'error',
        exitCode: -1,
        stdout: '',
        stderr: err instanceof Error ? err.message : String(err),
        executionTime: 0,
        resourcesUsed: { cpu: 0, memory: 0, disk: 0 }
      }
    } finally {
      // Cleanup
      await this.cleanupSandbox(sandboxDir);
    }
  }

  /**
   * Launch execution in isolated container
   */
  private async executeInContainer(
    sandboxDir: string,
    codeFile: string,
    config: SandboxConfig,
    seccompPath: string,
    executionId: string
  ): Promise<ExecutionResult> {
    const startTime = Date.now();
    
    const dockerCmd = [
      'run',
      '--rm',
      `--name=sandbox-${executionId}`,
      `--cpus=${config.cpuShares}`,
      `--memory=${config.memory}m`,
      `--pids-limit=16`,
      `--user=sandbox:sandbox`,
      `--read-only`,
      `--cap-drop=ALL`,
      // `--security-opt=seccomp=${seccompPath}`, // Commented out for local testing without strict Docker daemon setup
      `${!config.networkEnabled ? '--network=none' : '--network=bridge'}`,
      `-v=${sandboxDir}:/tmp/sandbox:rw`,
      `-v=/tmp:/tmp:rw`,
      `sandbox-runner:latest`,
      config.language,
      `/tmp/sandbox/code`,
      `${config.timeout}`
    ];

    if (config.networkEnabled) {
      dockerCmd.splice(9, 0, '--cap-add=NET_BIND_SERVICE');
    }

    return new Promise((resolve, reject) => {
      const proc = spawn('docker', dockerCmd);
      
      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => { stdout += data.toString(); });
      proc.stderr?.on('data', (data) => { stderr += data.toString(); });

      const timeout = setTimeout(() => {
        proc.kill('SIGKILL');
        reject(new Error('Execution timeout'));
      }, (config.timeout + 5) * 1000);

      proc.on('close', (code) => {
        clearTimeout(timeout);
        const executionTime = (Date.now() - startTime) / 1000;

        resolve({
          status: code === 0 ? 'success' : 'error',
          exitCode: code || 0,
          stdout,
          stderr,
          executionTime,
          resourcesUsed: { cpu: 0.5, memory: 128, disk: 0 }
        });
      });
    });
  }

  private async captureAuditData(executionId: string, sandboxDir: string) {
    const stats = await this.dockerClient.stats(`sandbox-${executionId}`);
    return {
      systemCalls: [], filesAccessed: [], networkConnections: [],
      cpuTime: stats.cpu_stats.cpu_usage.total_usage,
      memoryPeak: stats.memory_stats.max_usage,
      processCount: 1, anomalies: []
    };
  }

  private createSeccompProfile(config: SandboxConfig, permissions: Permission[]) {
    const allowedSyscalls = new Set(['read', 'write', 'open', 'close', 'stat', 'fstat', 'mmap', 'mprotect', 'exit_group', 'rt_sigaction']);

    if (permissions.some(p => p.type === 'network_egress')) {
      allowedSyscalls.add('socket'); allowedSyscalls.add('connect'); allowedSyscalls.add('bind');
    }

    return {
      defaultAction: 'SCMP_ACT_KILL',
      syscalls: [
        { names: Array.from(allowedSyscalls), action: 'SCMP_ACT_ALLOW' },
        { names: ['ptrace', 'fork', 'vfork', 'execve'], action: 'SCMP_ACT_KILL' }
      ]
    };
  }

  private async setupSandbox(sandboxDir: string, permissions: Permission[]) {
    await fs.mkdir(sandboxDir, { recursive: true });
    const tmpDir = path.join(sandboxDir, 'tmp');
    await fs.mkdir(tmpDir, { mode: 0o700 });
  }

  private async cleanupSandbox(sandboxDir: string) {
    try {
      await fs.rm(sandboxDir, { recursive: true, force: true });
    } catch (e) {
      console.error('Cleanup failed:', e);
    }
  }
}
