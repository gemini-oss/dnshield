#import "DNCTLCommands.h"

#import "DNCTLCommon.h"

void DNCTLPrintUsage(void) {
  printf("DNShield Control Utility\n\n");
  printf("Usage: dnshield-ctl [command] [options]\n\n");
  printf("Commands:\n");
  printf("  status          Show daemon and extension status\n");
  printf("  start           Start the DNShield daemon\n");
  printf("  stop            Stop the DNShield daemon\n");
  printf("  restart         Restart the DNShield daemon\n");
  printf("  enable          Enable DNS filtering\n");
  printf("  disable         Disable DNS filtering\n");
  printf("  config          Show or set configuration values\n");
  printf("  logs            Show or follow logs via unified logging\n");
  printf("  logs subsystems List DNShield subsystems/categories from logs\n");
  printf("  logs categories List unique categories across DNShield logs\n");
  printf("  version         Show version information\n");
  printf("  help            Show this help message\n");
  printf("\nOutput formatting (where applicable):\n");
  printf("  Append:  format <plist|json|yaml>\n");
  printf("  Examples: dnshield-ctl config format json\n");
  printf("            dnshield-ctl status format yaml\n");
}
