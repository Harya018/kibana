import logging
import subprocess

logger = logging.getLogger(__name__)

class ResponseExecutor:
    """
    Executes automated response actions (Containment/Remediation).
    """
    
    SAFE_MODE = True # If True, only log actions, do not execute.

    @staticmethod
    def block_ip(ip_address):
        """
        Simulates blocking an IP via Firewall.
        """
        cmd = f"netsh advfirewall firewall add rule name=\"Block {ip_address}\" dir=in action=block remoteip={ip_address}"
        
        if ResponseExecutor.SAFE_MODE:
            logger.info(f"[SAFE MODE] Would execute: {cmd}")
            return True, "Action simulated (Safe Mode)"
            
        try:
            # subprocess.run(cmd, shell=True, check=True) # Dangerous in prod without validation
            logger.info(f"Executed: {cmd}")
            return True, "IP Blocked successfully"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def disable_user(username):
        """
        Simulates disabling a user account.
        """
        cmd = f"net user {username} /active:no"
        
        if ResponseExecutor.SAFE_MODE:
            logger.info(f"[SAFE MODE] Would execute: {cmd}")
            return True, "Action simulated (Safe Mode)"
            
        try:
            # subprocess.run(cmd, shell=True, check=True)
            logger.info(f"Executed: {cmd}")
            return True, "User Disabled successfully"
        except Exception as e:
            return False, str(e)
            
    @staticmethod
    def execute_action(action_name, target):
        """
        Dispatcher for actions.
        """
        if action_name == "block_ip":
            return ResponseExecutor.block_ip(target)
        elif action_name == "disable_user":
            return ResponseExecutor.disable_user(target)
        else:
            return False, f"Unknown action: {action_name}"
