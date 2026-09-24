// Exercise Network.framework, including explicit Wi-Fi binding (Skywalk path).
#include <Network/Network.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Private SPI used by WebKit's NetworkRTCUtilitiesCocoa to preserve app identity.
extern void nw_parameters_set_source_application_by_bundle_id(nw_parameters_t, const char *);
int main(int argc, char **argv) {
    alarm(75);
    if (argc < 4 || argc > 5) {
        fprintf(stderr, "usage: %s tcp|udp HOST PORT [wifi]\n", argv[0]);
        return 64;
    }
    bool udp = !strcmp(argv[1], "udp");
    if (!udp && strcmp(argv[1], "tcp")) return 64;
    dispatch_queue_t q = dispatch_queue_create("probe", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    nw_parameters_t p = udp
        ? nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION)
        : nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    const char *app = getenv("PROBE_APP");
    if (app) nw_parameters_set_source_application_by_bundle_id(p, app);
    if (argc == 5) nw_parameters_set_required_interface_type(p, nw_interface_type_wifi);
    nw_endpoint_t e = nw_endpoint_create_host(argv[2], argv[3]);
    nw_connection_t c = nw_connection_create(e, p);
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, NSEC_PER_SEC, 0);
    dispatch_source_set_event_handler(timer, ^{
        static const char probe[] = "slipstream UDP leak probe";
        dispatch_data_t payload = dispatch_data_create(probe, sizeof(probe)-1, q, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
        nw_connection_send(c, payload, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t err) {
            printf("udp_send_error=%d\n", err ? nw_error_get_error_code(err) : 0); fflush(stdout);
        });
    });
    nw_connection_set_queue(c, q);
    nw_connection_set_state_changed_handler(c, ^(nw_connection_state_t state, nw_error_t error) {
        nw_path_t path = nw_connection_copy_current_path(c);
        printf("state=%d error=%d path_status=%d reason=%d\n", state, error ? nw_error_get_error_code(error) : 0, path ? nw_path_get_status(path) : 0, path ? nw_path_get_unsatisfied_reason(path) : 0);
        fflush(stdout);
        if (state == nw_connection_state_ready) {
            if (udp) dispatch_resume(timer);
            const char data[] = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
            dispatch_data_t payload = dispatch_data_create(data, sizeof(data)-1, q, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            nw_connection_send(c, payload, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t err) {
                printf("send_error=%d\n", err ? nw_error_get_error_code(err) : 0);
                fflush(stdout);
            });
            nw_connection_receive(c, 1, 1024, ^(dispatch_data_t content, nw_content_context_t context, bool complete, nw_error_t err) {
                (void)context; (void)complete;
                printf("received=%zu error=%d\n", content ? dispatch_data_get_size(content) : 0, err ? nw_error_get_error_code(err) : 0);
                fflush(stdout);
                dispatch_semaphore_signal(done);
            });
        }
        if (state == nw_connection_state_failed) dispatch_semaphore_signal(done);
    });
    nw_connection_start(c);
    int seconds = getenv("PROBE_SECONDS") ? atoi(getenv("PROBE_SECONDS")) : 6;
    if (seconds < 1 || seconds > 60) return 64;
    long timedout = dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, seconds*NSEC_PER_SEC));
    printf("timed_out=%d\n", timedout != 0);
    nw_connection_cancel(c);
    return 0;
}
