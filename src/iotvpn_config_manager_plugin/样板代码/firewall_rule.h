#ifndef _FILREWALL_RULE_H
#define _FIREWALL_RULE_H

struct connection;

void get_firewall_rule(struct connection* cnn);

void add_firewall_rule(struct connection* cnn);

void delete_firewall_rule(struct connection* cnn);

void modify_firewall_rule(struct connection* cnn);

void start_firewall_rule(struct connection* cnn);

void stop_firewall_rule(struct connection* cnn);

int init_firewall_rule();

#endif // _FIREWALL_RULE_H