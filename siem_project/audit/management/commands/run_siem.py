import time
import signal
import sys
from django.core.management.base import BaseCommand
from audit.correlation import CorrelationEngine

class Command(BaseCommand):
    help = 'Runs the SIEM Correlation Engine'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("Starting SIEM Correlation Engine..."))
        
        def signal_handler(sig, frame):
            self.stdout.write(self.style.WARNING("\nStopping SIEM Engine..."))
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        
        while True:
            try:
                self.stdout.write("Running correlation rules...")
                count = CorrelationEngine.run_correlation_rules()
                if count > 0:
                    self.stdout.write(self.style.SUCCESS(f"Created {count} new incidents."))
                else:
                    self.stdout.write("No new incidents.")
                
                # Sleep for 1 minute (simulation speed)
                time.sleep(60)
                
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error in Correlation Loop: {e}"))
                time.sleep(60)
