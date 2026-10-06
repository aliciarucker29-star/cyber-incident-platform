#include "Incident.h"

#include <iostream>

Incident::Incident()
: incidentId(0)
{
}

void Incident::display() const
{
std::cout << "\n=== INCIDENT ===\n";
std::cout << "Incident ID: " << incidentId << '\n';
std::cout << "Title: " << title << '\n';
std::cout << "Username: " << username << '\n';
std::cout << "Source IP: " << sourceIp << '\n';
std::cout << "Hostname: " << hostname << '\n';
std::cout << "Severity: " << severity << '\n';
std::cout << "Start Time: " << startTime << '\n';
std::cout << "End Time: " << endTime << '\n';

std::cout << "Related Detections:\n";

for (const std::string& rule : detectionRules)
{
std::cout << " - " << rule << '\n';
}

std::cout << "Evidence Event IDs: ";

for (long long id : evidenceEventIds)
{
std::cout << id << " ";
}

std::cout << '\n';
}