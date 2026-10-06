#ifndef EVENT_H
#define EVENT_H

#include <string>

class Event
{
public:
    long long eventId;
    std::string eventTimestamp;
    std::string eventType;
    std::string action;
    std::string username;
    std::string sourceIp;
    std::string hostname;
    std::string severity;
    std::string sourceSystem;

    Event();

    Event(
        long long eventId,
        const std::string& eventTimestamp,
        const std::string& eventType,
        const std::string& action,
        const std::string& username,
        const std::string& sourceIp,
        const std::string& hostname,
        const std::string& severity,
        const std::string& sourceSystem
     );

     void display() const;
     long long timestampToEpoch() const;
};

#endif