dnl modules enabled in this directory by default

dnl APACHE_MODULE(name, helptext[, objects[, structname[, default[, config]]]])

APACHE_MODPATH_INIT(com/snert/watch)

watch_objs="mod_watch.lo Memory.lo SharedHash.lo NetworkTable.lo"
APACHE_MODULE(watch, Monitoring interface for Apache & MRTG, $watch_objs, , no)

APACHE_MODPATH_FINISH

