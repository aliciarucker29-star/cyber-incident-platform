#include "Detector.h"

#include <algorithm>
#include <unordered_map>
#include <vector>

// ============================================================
// Rule 1:
// Detect 5 or more failed login attempts for the same user
// within a 10-minute window.
// ============================================================

std::vector<DetectionResult> Detector::detectFailedLogins(
    const std::vector<Event>& events
) const
{
    std::vector<DetectionResult> results;

    std::unordered_map<std::string, std::vector<const Event*>>
        failedLogins;

    // Group failed authentication events by username.
    for (const Event& event : events)
    {
        if (event.eventType == "authentication" &&
            event.action == "login_failed")
        {
            failedLogins[event.username].push_back(&event);
        }
    }

    // Check each user independently.
    for (auto& entry : failedLogins)
    {
        std::vector<const Event*>& userEvents = entry.second;

        std::sort(
            userEvents.begin(),
            userEvents.end(),
            [](const Event* a, const Event* b)
            {
                return a->timestampToEpoch() <
                       b->timestampToEpoch();
            }
        );

        for (std::size_t start = 0;
             start < userEvents.size();
             ++start)
        {
            long long startTime =
                userEvents[start]->timestampToEpoch();

            if (startTime < 0)
            {
                continue;
            }

            std::vector<long long> evidenceIds;

            for (std::size_t end = start;
                 end < userEvents.size();
                 ++end)
            {
                long long endTime =
                    userEvents[end]->timestampToEpoch();

                if (endTime < 0)
                {
                    continue;
                }

                long long difference =
                    endTime - startTime;

                if (difference <= 600)
                {
                    evidenceIds.push_back(
                        userEvents[end]->eventId
                    );
                }
                else
                {
                    break;
                }
            }

            if (evidenceIds.size() >= 5)
            {
                DetectionResult result;

                result.detected = true;

                result.ruleName =
                    "Repeated Failed Authentication";

                result.description =
                    "Five or more failed login attempts detected "
                    "for the same user within 10 minutes.";

                result.severity = "high";
                result.username = entry.first;
                result.eventIds = evidenceIds;

                results.push_back(result);

                // Stop looking for additional Rule 1 windows
                // for this user, but continue checking other users.
                break;
            }
        }
    }

    return results;
}


// ============================================================
// Rule 2:
// Detect at least 3 failed logins followed by a successful
// login for the same user within 10 minutes.
// ============================================================

std::vector<DetectionResult> Detector::detectFailedThenSuccess(
    const std::vector<Event>& events
) const
{
    std::vector<DetectionResult> results;

    // Group all authentication events by username.
    std::unordered_map<std::string, std::vector<const Event*>>
        userEvents;

    for (const Event& event : events)
    {
        if (event.eventType == "authentication")
        {
            userEvents[event.username].push_back(&event);
        }
    }

    // Process each user separately.
    for (auto& entry : userEvents)
    {
        std::vector<const Event*>& eventsForUser =
            entry.second;

        std::sort(
            eventsForUser.begin(),
            eventsForUser.end(),
            [](const Event* a, const Event* b)
            {
                return a->timestampToEpoch() <
                       b->timestampToEpoch();
            }
        );

        bool userDetected = false;

        for (std::size_t successIndex = 0;
             successIndex < eventsForUser.size();
             ++successIndex)
        {
            const Event* successEvent =
                eventsForUser[successIndex];

            if (successEvent->action != "login_success")
            {
                continue;
            }

            long long successTime =
                successEvent->timestampToEpoch();

            if (successTime < 0)
            {
                continue;
            }

            std::vector<long long> failedEventIds;

            for (std::size_t failedIndex = 0;
                 failedIndex < successIndex;
                 ++failedIndex)
            {
                const Event* failedEvent =
                    eventsForUser[failedIndex];

                if (failedEvent->action != "login_failed")
                {
                    continue;
                }

                long long failedTime =
                    failedEvent->timestampToEpoch();

                if (failedTime < 0)
                {
                    continue;
                }

                long long difference =
                    successTime - failedTime;

                if (difference >= 0 &&
                    difference <= 600)
                {
                    failedEventIds.push_back(
                        failedEvent->eventId
                    );
                }
            }

            if (failedEventIds.size() >= 3)
            {
                DetectionResult result;

                result.detected = true;

                result.ruleName =
                    "Failed Logins Followed by Success";

                result.description =
                    "Multiple failed login attempts were followed "
                    "by a successful login for the same user "
                    "within 10 minutes.";

                result.severity = "high";
                result.username = entry.first;

                result.eventIds = failedEventIds;

                // Add the successful login as evidence.
                result.eventIds.push_back(
                    successEvent->eventId
                );

                results.push_back(result);

                userDetected = true;
                break;
            }
        }

        // Explicitly show that we only create one Rule 2
        // detection per user.
        if (userDetected)
        {
            continue;
        }
    }

    return results;
}