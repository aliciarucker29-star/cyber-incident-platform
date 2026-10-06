#include "IndicatorEnricher.h"

#include <string>

void IndicatorEnricher::enrich(Indicator& indicator) const
{
if (indicator.type != "ip_address")
{
indicator.reputation = "unknown";
return;
}

const std::string& ip = indicator.value;

// Private/local IPv4 ranges
if (ip.rfind("10.", 0) == 0 ||
ip.rfind("192.168.", 0) == 0 ||
ip.rfind("172.16.", 0) == 0 ||
ip.rfind("172.17.", 0) == 0 ||
ip.rfind("172.18.", 0) == 0 ||
ip.rfind("172.19.", 0) == 0 ||
ip.rfind("172.20.", 0) == 0 ||
ip.rfind("172.21.", 0) == 0 ||
ip.rfind("172.22.", 0) == 0 ||
ip.rfind("172.23.", 0) == 0 ||
ip.rfind("172.24.", 0) == 0 ||
ip.rfind("172.25.", 0) == 0 ||
ip.rfind("172.26.", 0) == 0 ||
ip.rfind("172.27.", 0) == 0 ||
ip.rfind("172.28.", 0) == 0 ||
ip.rfind("172.29.", 0) == 0 ||
ip.rfind("172.30.", 0) == 0 ||
ip.rfind("172.31.", 0) == 0)
{
indicator.reputation = "private";
indicator.context =
"Private IP address observed in incident evidence";

return;
}

// Public IP: no external threat-intelligence lookup yet.
indicator.reputation = "unknown";
indicator.context =
"Public IP address observed; external reputation not yet checked";
}