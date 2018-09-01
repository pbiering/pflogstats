pflogstats.pl and it's modules is an extended version of "pflogsumm.pl"


Attention:
==========

Following options have changed:

* pflogsumm.pl	=> pflogstats.pl
* -d		=> -r|--range
* -h		=> --top



Usage of intermediate storage:
==============================

* first, parse logfile and save data to XML file
cat /var/log/maillog | pflogstats.pl --type reject --type uce --type av --save-intermediate-xml pflogstats-yesterday.xml --range yesterday --format none

* second, read intermediate data from XML file and display result
pflogstats.pl --type av --load-intermediate-xml pflogstats-yesterday.xml --format treeview

pflogstats.pl --type uce --load-intermediate-xml pflogstats-yesterday.xml --format treeview --show_domain_list domain.example

pflogstats.pl --type reject --load-intermediate-xml pflogstats-yesterday.xml --format treeview --show_user_list info@domain.example
