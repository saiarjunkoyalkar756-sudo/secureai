import re

with open('src/sandbox/sandbox-engine.ts', 'r') as f:
    code = f.read()

# Add getSandboxUser method
get_sandbox_user = """
  private getSandboxUser(): { uid?: number; gid?: number } {
    if (process.platform !== 'linux') return {};
    try {
      const uid = parseInt(require('child_process').execSync('id -u sandbox', { encoding: 'utf-8' }).trim(), 10);
      const gid = parseInt(require('child_process').execSync('id -g sandbox', { encoding: 'utf-8' }).trim(), 10);
      return { uid, gid };
    } catch {
      return {};
    }
  }

  private runProcess("""

code = code.replace("  private runProcess(", get_sandbox_user)

# Modify runProcess spawn
spawn_old = """      const proc = spawn(command, args, {
        cwd: sandboxDir,
        env: safeEnv,
        stdio: ['pipe', 'pipe', 'pipe'],
        timeout: cfg.timeout * 1000,
        windowsHide: true
      });"""

spawn_new = """      const { uid, gid } = this.getSandboxUser();

      const proc = spawn(command, args, {
        cwd: sandboxDir,
        env: safeEnv,
        stdio: ['pipe', 'pipe', 'pipe'],
        uid,
        gid,
        windowsHide: true
      });"""

code = code.replace(spawn_old, spawn_new)

# Modify kill logic for SIGTERM then SIGKILL
kill_old = """      const timer = setTimeout(() => {
        killed = true;
        proc.kill('SIGKILL');
      }, cfg.timeout * 1000);"""

kill_new = """      const timer = setTimeout(() => {
        killed = true;
        proc.kill('SIGTERM'); // Grace period request
        setTimeout(() => {
          try { proc.kill('SIGKILL'); } catch (e) {} // Hard kill zombie
        }, 1000);
      }, cfg.timeout * 1000);"""

code = code.replace(kill_old, kill_new)

# Truncate branch kill logic update
trunc_kill_old = """        if (stdout.length > 1024 * 1024) {
          killed = true;
          proc.kill('SIGKILL');
        }"""

trunc_kill_new = """        if (stdout.length > 1024 * 1024) {
          killed = true;
          proc.kill('SIGKILL');
        }"""
        
trunc_kill_err_old = """        if (stderr.length > 1024 * 1024) {
          killed = true;
          proc.kill('SIGKILL');
        }"""

with open('src/sandbox/sandbox-engine.ts', 'w') as f:
    f.write(code)
