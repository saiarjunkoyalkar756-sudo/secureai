export type PermissionType = 
  | 'file_read' 
  | 'file_write' 
  | 'network_egress' 
  | 'subprocess_exec' 
  | 'env_read'
  | 'gpu_access';

export interface Permission {
  id: string;
  type: PermissionType;
  resource: string; // "/path/to/file", "*.example.com", "MY_SECRET"
  action: 'allow' | 'deny' | 'audit_only';
  conditions?: {
    maxDataSize?: number;        // KB
    maxExecutionTime?: number;   // seconds
    maxNetworkBandwidth?: number; // Mbps
    requiresApproval?: boolean;
    approverRole?: 'admin' | 'security' | 'owner';
  };
  createdAt: Date;
  createdBy: string;
}

export interface PermissionRequest {
  id: string;
  executionId: string;
  requestedPermissions: Permission[];
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  requestedBy: string;
  approvedBy?: string;
  approvalTime?: Date;
  expiresAt: Date;
}
