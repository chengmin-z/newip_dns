#include <stdio.h>

#include "dns_table.h"

int main() {
    struct dns_table *table = importDomainTable("dns_data.txt");
}