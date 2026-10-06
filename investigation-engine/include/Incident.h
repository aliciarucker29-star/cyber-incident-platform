#ifndef INCIDENT_H
#define INCIDENT_H

#include <string>
#include <vector>

class Incident
{
public:
long long incidentId;

std::string title;
std::string username;
std::string sourceIp;
std::string hostname;
std::string severity;
std::string startTime;
std::string endTime;

std::vector<std::string> detectionRules;
std::vector<long long> evidenceEventIds;

Incident();

void display() const;
};

#endif