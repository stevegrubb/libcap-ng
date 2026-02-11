#ifndef NETCAP_ADVANCED_H
#define NETCAP_ADVANCED_H

struct netcap_opts {
	int advanced;
	int json;
};

int netcap_advanced_main(const struct netcap_opts *opts);

#endif
