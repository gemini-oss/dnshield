//
// dnshield-xpc.m
// Simple XPC client for dnshield daemon
//

#import <Foundation/Foundation.h>
#import <xpc/xpc.h>

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc < 2) {
      fprintf(stderr, "Usage: %s <command>\n", argv[0]);
      fprintf(stderr, "Commands: status, enable, disable\n");
      return 1;
    }

    const char* command = argv[1];

    // Create XPC connection
    xpc_connection_t connection = xpc_connection_create_mach_service(
        "com.dnshield.daemon.xpc", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    xpc_connection_set_event_handler(connection, ^(xpc_object_t event){
                                         // Ignore events for this simple tool
                                     });

    xpc_connection_resume(connection);

    // Create message
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_string(message, "command", command);

    // Send message and wait for reply
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(connection, message);

    if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
      fprintf(stderr, "XPC error: %s\n",
              xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION));
      return 1;
    }

    // Handle reply based on command
    if (strcmp(command, "status") == 0) {
      bool daemonRunning = xpc_dictionary_get_bool(reply, "daemonRunning");
      bool extensionInstalled = xpc_dictionary_get_bool(reply, "extensionInstalled");
      bool filterEnabled = xpc_dictionary_get_bool(reply, "filterEnabled");
      int64_t pid = xpc_dictionary_get_int64(reply, "pid");

      printf("Daemon: %s (PID: %lld)\n", daemonRunning ? "Running" : "Not running", pid);
      printf("Extension: %s\n", extensionInstalled ? "Installed" : "Not installed");
      printf("Filter: %s\n", filterEnabled ? "Enabled" : "Disabled");
    } else {
      bool success = xpc_dictionary_get_bool(reply, "success");
      if (success) {
        printf("Command '%s' executed successfully\n", command);
      } else {
        const char* error = xpc_dictionary_get_string(reply, "error");
        fprintf(stderr, "Command failed: %s\n", error ?: "Unknown error");
        return 1;
      }
    }

    xpc_connection_cancel(connection);

    return 0;
  }
}
