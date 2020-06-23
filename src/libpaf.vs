# This file holds a list of symbols to be exported in the shared library
{
global:
	paf_attach;
	paf_publish;
	paf_modify;
	paf_unpublish;
	paf_subscribe;
	paf_unsubscribe;
	paf_fd;
	paf_process;
	paf_detach;
	paf_close;
	paf_filter_escape;

	paf_props_create;
	paf_props_add;
	paf_props_add_int64;
	paf_props_add_str;
	paf_props_get;
	paf_props_get_one;
	paf_props_foreach;
	paf_props_equal;
	paf_props_num_values;
	paf_props_num_names;
	paf_props_clone;
	paf_props_destroy;

	paf_value_is_int64;
	paf_value_is_str;
	paf_value_int64_create;
	paf_value_int64;
	paf_value_str_create;
	paf_value_str;
	paf_value_equal;
	paf_value_clone;
	paf_value_destroy;

	paf_strerror;
local:
    *;
};
