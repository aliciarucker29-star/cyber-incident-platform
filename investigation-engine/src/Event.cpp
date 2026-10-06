#include "Event.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>

Event::Event()
    : eventId(0)
{
}

Event::Event(
    long long eventId,
    const std::string& eventTimestamp,
    const std::string& eventType,
    const std::string& action,
    const std::string& username,
    const std::string& sourceIp,
    const std::string& hostname,
    const std::string& severity,
    const std::string& sourceSystem
)
    : eventId(eventId),
      eventTimestamp(eventTimestamp),
      eventType(eventType),
      action(action),
      username(username),
      sourceIp(sourceIp),
      hostname(hostname),
      severity(severity),
      sourceSystem(sourceSystem)
{
}

void Event::display() const
{
    std::cout << "Event ID: " << eventId << '\n';
    std::cout << "Timestamp: " << eventTimestamp << '\n';
    std::cout << "Type: " << eventType << '\n';
    std::cout << "Action: " << action << '\n';
    std::cout << "Username: " << username << '\n';
    std::cout << "Source IP: " << sourceIp << '\n';
    std::cout << "Hostname: " << hostname << '\n';
    std::cout << "Severity: " << severity << '\n';
    std::cout << "Source System: " << sourceSystem << '\n';
}


long long Event::timestampToEpoch() const
{
    std::tm timeInfo = {};

    std::istringstream stream(eventTimestamp);

    stream >> std::get_time(
        &timeInfo,
        "%Y-%m-%dT%H:%M:%S"
    );

    if (stream.fail())
    {
        return -1;
    }

    std::time_t timestamp = std::mktime(&timeInfo);

    return static_cast<long long>(timestamp);
}