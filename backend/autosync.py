import logging
import sys
from datetime import datetime
from pathlib import Path
import win32com.client
import subprocess

def setup_logging(base_dir: Path):
    log_dir = base_dir / 'logs'
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / f'autosync_{datetime.now().strftime("%Y%m%d")}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logging.info('-' * 80)
    logging.info('AutoSync Monitoring Session Started')
    
    return log_dir

def create_scheduled_task(task_name: str, script_path: str):
    try:
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()
        
        root_folder = scheduler.GetFolder('\\')
        task_def = scheduler.NewTask(0)
        
        task_def.RegistrationInfo.Description = f"Daily CVE Web Sync Monitoring - {task_name}"
        task_def.Settings.Enabled = True
        task_def.Settings.Hidden = False
        task_def.Settings.RunOnlyIfNetworkAvailable = True
        
        trigger = task_def.Triggers.Create(2)  
        trigger.StartBoundary = datetime.now().replace(hour=9, minute=34, second=0).isoformat()
        trigger.Enabled = True
        trigger.DaysInterval = 1
        
        action = task_def.Actions.Create(0)
        action.Path = sys.executable
        action.Arguments = f'"{script_path}"'
        
        root_folder.RegisterTaskDefinition(
            task_name,task_def,6,None,None,0)
        
        logging.info(f"Scheduled task '{task_name}' created successfully for {trigger.StartBoundary} daily run")
        return True
        
    except Exception as e:
        logging.error(f"Failed to create scheduled task: {e}")
        return False

def run_web_sync(script_path: Path, log_dir: Path):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        web_sync_log = log_dir / f'web_sync_{timestamp}.log'
        
        logging.info(f"Starting web_sync.py execution, logging to: {web_sync_log}")
        
        with web_sync_log.open('w') as log_file:
            process = subprocess.Popen(
                [sys.executable, str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            for line in process.stdout:
                log_file.write(line)
                log_file.flush()
                logging.info(f"WebSync: {line.strip()}")
                
        process.wait()
        
        if process.returncode == 0:
            logging.info("Web sync execution completed successfully")
            return True
        else:
            logging.error(f"Web sync execution failed with return code: {process.returncode}")
            return False
            
    except Exception as e:
        logging.error(f"Error running web sync script: {e}")
        return False

def monitor_web_sync_status(script_path: Path):
    try:
        if not script_path.exists():
            logging.error(f"Web sync script not found: {script_path}")
            return False
            
        file_stats = script_path.stat()
        
        logging.info(f"Web sync script check - Path: {script_path}")
        logging.info(f"File size: {file_stats.st_size:,} bytes")
        logging.info(f"Last modified: {datetime.fromtimestamp(file_stats.st_mtime)}")
        
        try:
            with script_path.open('r') as f:
                first_line = f.readline()
            logging.info("Web sync script is readable: True")
            return True
        except Exception as e:
            logging.error(f"Web sync script read error: {e}")
            return False
            
    except Exception as e:
        logging.error(f"Error checking web sync script: {e}")
        return False

def main():
    base_dir = Path(__file__).parent
    script_path = base_dir / 'web_sync.py'
    
    log_dir = setup_logging(base_dir)
    logging.info(f"Base directory: {base_dir}")
    logging.info(f"Web sync script path: {script_path}")
    
    try:
        if monitor_web_sync_status(script_path):
            logging.info("Web sync script status check completed")
            
            if run_web_sync(script_path, log_dir):
                logging.info("Web sync execution completed")
            else:
                logging.warning("Web sync execution failed")
        else:
            logging.warning("Web sync script status check failed")
        
        task_name = 'Daily_CVE_Sync'
        create_scheduled_task(task_name, str(script_path))
        
    except Exception as e:
        logging.error(f"Unexpected error during monitoring: {e}")
        sys.exit(1)
    finally:
        logging.info("Monitoring session ended")
        logging.info('-' * 80)

if __name__ == '__main__':
    main()