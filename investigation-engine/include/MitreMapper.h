#ifndef MITRE_MAPPER_H
#define MITRE_MAPPER_H

#include "Incident.h"

#include <string>
#include <vector>

struct MitreMapping
{
    std::string techniqueId;
    std::string techniqueName;
    std::string tactic;
    std::string confidence;
    std::string reason;
};

class MitreMapper
{
public:
    std::vector<MitreMapping> map(
        const Incident& incident
    ) const;
};

#endif