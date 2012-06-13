
#include <unistd.h> // STDIN_FILENO
#include <string.h> //strlen
#include <ctype.h>  // isspace
#include <stdlib.h> // strtol

#include "config_handler.h"
#include "ev_handler.h"
#include "export_handler.h"

#include "logger.h"
#include "netcon.h"
#include "settings.h"
#include "helper.h"
#include "netcon.h"




typedef char* (*set_cfg_fct_t)(unsigned long mid, char* cmd_msg);

// !! do not change order !!
typedef struct cfg_fct{
  char cmd;
  set_cfg_fct_t fct;
  const char* desc;
}
cfg_fct_t;

// -----------------------------------------------------------------------------
// Prototypes
// -----------------------------------------------------------------------------
/* -- runtime configuration -- */
void user_input_cb(EV_P_ ev_watcher *w, int revents);
int runtime_configuration_cb(char*);

char* configuration_help(unsigned long mid, char *msg);
char* configuration_set_template(unsigned long mid, char *msg);
char* configuration_set_filter(unsigned long mid, char *msg);
char* configuration_set_export_to_probestats(unsigned long mid, char *msg);
char* configuration_set_export_to_ifstats(unsigned long mid, char *msg);
char* configuration_set_export_to_pktid(unsigned long mid, char *msg);
char* configuration_set_min_selection(unsigned long mid, char *msg);
char* configuration_set_max_selection(unsigned long mid, char *msg);
char* configuration_set_ratio(unsigned long mid, char *msg);

set_cfg_fct_t getFunction(char cmd);

void config_handler_init(EV_P) {
    LOGGER_info("call");

    // listen to standart input
    LOGGER_info("register event io: user-input");
    event_register_io_r(EV_A_ user_input_cb, STDIN_FILENO);

    // register runtime configuration callback to netcon
    LOGGER_info("register netcon: runtime configuration");
    netcon_register(runtime_configuration_cb);

}

//typedef struct {
//  char cmd;
//  set_cfg_fct_t fct;
//  const char* desc;
//}
//cfg_fct_t;

// register available configuration functions
// to the config function array
cfg_fct_t configuration_fct[] = {
    { '?', &configuration_help, "INFO: -? this help\n"},
    { 'h', &configuration_help, "INFO: -h this help\n"},
    { 'r', &configuration_set_ratio, "INFO: -r capturing ratio in %\n"},
    { 'm', &configuration_set_min_selection, "INFO: -m capturing selection range min (hex|int)\n"},
    { 'M', &configuration_set_max_selection, "INFO: -M capturing selection range max (hex|int)\n"},
    { 'f', &configuration_set_filter, "INFO: -f bpf filter expression\n"},
    { 't', &configuration_set_template, "INFO: -t template (ts|min|lp)\n"},
    { 'I', &configuration_set_export_to_pktid, "INFO: -I pktid export interval (s)\n"},
    { 'J', &configuration_set_export_to_probestats, "INFO: -J porbe stats export interval (s)\n"},
    { 'K', &configuration_set_export_to_ifstats, "INFO: -K interface stats export interval (s)\n"}
};

char cfg_response[256];
#define SET_CFG_RESPONSE(...) snprintf(cfg_response, sizeof(cfg_response), "" __VA_ARGS__);
#define CFG_RESPONSE cfg_response

// dummy function to prevent segmentation fault
char* unknown_cmd_fct(unsigned long id, char* msg) {
    LOGGER_warn("unknown command received: id=%lu, msg=%s", id, msg);
    return "unknown command received";
}

cfg_fct_t* get_cfg_fct(char cmd) {
    int i = 0;
    int length = sizeof (configuration_fct) / sizeof (cfg_fct_t);

    for (i = 0; i < length; ++i) {
        if (cmd == configuration_fct[i].cmd) {
            return &configuration_fct[i];
        }
    }
    LOGGER_warn("unknown command received: cmd=%c", cmd);
    return NULL;
}

set_cfg_fct_t getFunction(char cmd) {
    cfg_fct_t* f = get_cfg_fct(cmd);
    if (NULL != f) {
        return f->fct;
    } else {
        LOGGER_warn("unknown command received: cmd=%c", cmd);
        return unknown_cmd_fct;
    }
}

void user_input_cb(EV_P_ ev_watcher *w, int revents) {
    char buffer[129];
    //int   i = 0;
    //char  c = EOF;

    //while( '\n' != (c = fgetc(stdin)) ) {
    //if( i < sizeof(buffer)-1 ) {
    //buffer[i] = c;
    //}
    //++i;
    //fprintf(stderr, "c= %c\n", c);
    //}
    //buffer[i] = '\0';
    //fprintf(stderr, "%s\n", buffer);
    //exit(0);


    //if( 0 != buffer[0] ) {
    if (NULL != fgets(buffer, sizeof (buffer), stdin)) {
        //fscanf( stdin, "%5c", buffer );
        //LOGGER_info("user input: %s\n", buffer);
        //fprintf(stdout,"user input: %s", buffer);
        if (0 == strncmp(buffer, "exit", 4) ||
                0 == strncmp(buffer, "quit", 4)) {
            exit(0);
        }

        char* b = buffer;
        while (!isalpha(*b) && (*b != '\0')) ++b;
        if ('\0' == *b) return;
        char cmd = *b;
        ++b;

        // remove leading whitespaces
        while (isspace(*b)) ++b;
        //r_trim(b);

        //fprintf(stdout,"user input: [%c: '%s']\n", cmd, b);
        char* rsp_msg = (*getFunction(cmd))(1, b);
        fprintf(stdout, "%s", rsp_msg);

        //char msg[strlen(buffer+1+7)];
        //sprintf( msg, "mid:1 -%s", buffer );
        //runtime_configuration_cb( msg );
    }
}

/**
 * initial cb function;
 * selection of runtime configuration commands
 * command: "mid: <id> -<cmd> <value>
 * @param cmd string
 *
 * returns: 1 consumed, 0 otherwise
 */
int runtime_configuration_cb(char* conf_msg) {
    unsigned long mID = 0; // session id
    int matches;

    LOGGER_debug("configuration message received: '%s'", conf_msg);
    // check prefix: "mid: <id>"
    matches = sscanf(conf_msg, "mid: %lu ", &mID);
    if (1 == matches) {
        LOGGER_debug("Message ID: %lu", mID);

        // fetch command from string starting with hyphen '-'
        char cmd = '?';
        int length = strlen(conf_msg);

        int i = 0;
        for (i = 0; i < length; ++i, ++conf_msg) {
            if ('-' == *conf_msg) {
                // get command
                ++conf_msg;
                cmd = *conf_msg;
                ++conf_msg;

                // remove leading whitespaces
                while (isspace(*conf_msg))
                    ++conf_msg;

                // execute command
                LOGGER_debug("configuration command '%c': %s", cmd, conf_msg);

                char* rsp_msg = (*getFunction(cmd))(mID, conf_msg);

                int i;
                for (i = 0; i < g_options.number_interfaces; i++) {
                    LOGGER_debug("==> %s", rsp_msg);
                    export_data_sync(&if_devices[i]
                            , ev_now(EV_DEFAULT) * 1000
                            , mID
                            , 0
                            , rsp_msg);
                }
                return NETCON_CMD_MATCHED;
            }
        }
    }

    return NETCON_CMD_UNKNOWN;
}

/**
 * send available command
 * command: h,?
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_help(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);
    static char* response = NULL;

    cfg_fct_t* cfg_f = get_cfg_fct(*msg);
    if (NULL != cfg_f) {
        return (char*) cfg_f->desc;
    }
    else {
        if (NULL == response) {
            int i;
            int size = 1;
            int length = sizeof (configuration_fct) / sizeof (cfg_fct_t);

            for (i = 0; i < length; ++i) {
                size += strlen(configuration_fct[i].desc);
            }
            response = (char*) malloc(size + 1);

            char* tmp = response;
            for (i = 0; i < length; ++i) {
                strcpy(tmp, configuration_fct[i].desc);
                tmp += strlen(configuration_fct[i].desc);
            }
        }
        return response;
    }
}

/**
 * command: t <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_template(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    uint32_t t_id = parse_template(msg);
    if (-1 == t_id) {
        LOGGER_warn("unknown template: %s", msg);
        SET_CFG_RESPONSE("INFO: unknown template: %s", msg);
    }
    else {
        // TODO: handling for different devices
        int i = 0;
        for (i = 0; i < getOptions()->number_interfaces; ++i) {
            // reset all device specific templates
            if_devices[i].template_id = -1;
        }
        getOptions()->templateID = t_id;
        SET_CFG_RESPONSE("INFO: new template set: %s", msg);
    }
    return CFG_RESPONSE;
}

/**
 * command: f <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_filter(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    if (-1 == set_all_filter(msg)) {
        LOGGER_error("error setting filter: %s", msg);
        SET_CFG_RESPONSE("INFO: error setting filter: %s", msg);
    }
    else {
        SET_CFG_RESPONSE("INFO: new filter expression set: %s", msg);
    }
    return CFG_RESPONSE;
}

/**
 * command: J <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_export_to_probestats(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    int new_timeout = strtol(msg, NULL, 0);
    if (0 <= new_timeout) {
        export_timer_stats->repeat = new_timeout;
        ev_timer_again(EV_DEFAULT, export_timer_stats);

        SET_CFG_RESPONSE("INFO: new probestats export timeout set: %s", msg);
    } else {
        SET_CFG_RESPONSE("INFO: probestats export timeout NOT changed");
    }
    return CFG_RESPONSE;
}

/**
 * command: K <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_export_to_ifstats(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    int new_timeout = strtol(msg, NULL, 0);
    if (0 <= new_timeout) {
        export_timer_sampling->repeat = new_timeout;
        ev_timer_again(EV_DEFAULT, export_timer_sampling);

        SET_CFG_RESPONSE("INFO: new ifstats export timeout set: %s", msg);
    } else {
        SET_CFG_RESPONSE("INFO: ifstats export timeout NOT changed");
    }
    return CFG_RESPONSE;
}

/**
 * command: I <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_export_to_pktid(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    int new_timeout = strtol(msg, NULL, 0);
    if (0 <= new_timeout) {
        export_timer_pkid->repeat = new_timeout;
        ev_timer_again(EV_DEFAULT, export_timer_pkid);

        SET_CFG_RESPONSE("INFO: new packet export timeout set: %s", msg);
    } else {
        SET_CFG_RESPONSE("INFO: packet export timeout NOT changed");
    }
    return CFG_RESPONSE;
}

/**
 * command: m <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_min_selection(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    uint32_t value = set_sampling_lowerbound(&g_options, msg);
    SET_CFG_RESPONSE("INFO: minimum selection range set: %d", value);

    return CFG_RESPONSE;
}

/**
 * command: M <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_max_selection(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    uint32_t value = set_sampling_upperbound(&g_options, msg);
    SET_CFG_RESPONSE("INFO: maximum selection range set: %d", value);

    return CFG_RESPONSE;
}

/**
 * command: r <value>
 * returns: 1 consumed, 0 otherwise
 */
char* configuration_set_ratio(unsigned long mid, char *msg) {
    LOGGER_debug("Message ID: %lu", mid);

    /* currently sampling ratio is equal for all devices */
    if (-1 == set_sampling_ratio(&g_options, msg)) {
        LOGGER_error("error setting sampling ration: %s", msg);
        SET_CFG_RESPONSE("INFO: error setting sampling ration: %s", msg);
    }
    else {
        SET_CFG_RESPONSE("INFO: new sampling ratio set: %s", msg);
    }
    return CFG_RESPONSE;
}

