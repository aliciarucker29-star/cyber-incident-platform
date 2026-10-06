#include <iostream>
#include <vector>
#include <string>
#include <fstream>

#include "Event.h"
#include "EventLoader.h"
#include "Detector.h"
#include "Incident.h"
#include "Correlator.h"
#include "Timeline.h"
#include "IndicatorExtractor.h"
#include "IndicatorEnricher.h"
#include "Indicator.h"
#include "RiskScorer.h"
#include "MitreMapper.h"

void printDetection(const DetectionResult& result)
{
    if (!result.detected)
    {
        return;
    }

    std::cout << "[ALERT] Detection triggered!\n";
    std::cout << "Rule: " << result.ruleName << '\n';
    std::cout << "Description: " << result.description << '\n';
    std::cout << "Severity: " << result.severity << '\n';
    std::cout << "Username: " << result.username << '\n';

    std::cout << "Evidence Event IDs: ";

    for (long long id : result.eventIds)
    {
        std::cout << id << " ";
    }

    std::cout << "\n\n";
}

int main()
{
    std::cout
        << "=== Cyber Incident Investigation Engine ===\n\n";

    // --------------------------------------------------
    // LOAD EVENTS
    // --------------------------------------------------

    EventLoader loader;

    std::vector<Event> events =
        loader.loadFromJson("events.json");

    std::cout
        << "Loaded "
        << events.size()
        << " events from events.json.\n\n";

    if (events.empty())
    {
        std::cout
            << "No events available for investigation.\n";

        return 1;
    }

    // --------------------------------------------------
    // DETECTION
    // --------------------------------------------------

    Detector detector;

    std::vector<DetectionResult> detections;

    std::cout
        << "--- Rule 1: Repeated Failed Authentication ---\n";

    std::vector<DetectionResult> failedLoginResults =
        detector.detectFailedLogins(events);

    for (const DetectionResult& result : failedLoginResults)
    {
        printDetection(result);
        detections.push_back(result);
    }

    std::cout
        << "--- Rule 2: Failed Logins Followed by Success ---\n";

    std::vector<DetectionResult> failedThenSuccessResults =
        detector.detectFailedThenSuccess(events);

    for (const DetectionResult& result :
         failedThenSuccessResults)
    {
        printDetection(result);
        detections.push_back(result);
    }

    std::cout
        << "Total Detections: "
        << detections.size()
        << "\n\n";

    // --------------------------------------------------
    // CORRELATION
    // --------------------------------------------------

    Correlator correlator;

    std::vector<Incident> incidents =
        correlator.correlate(
            detections,
            events
        );

    if (incidents.empty())
    {
        std::cout
            << "No incidents created from current detections.\n";

        return 0;
    }

    std::cout
        << "Total Incidents: "
        << incidents.size()
        << '\n';

    // --------------------------------------------------
    // INVESTIGATION COMPONENTS
    // --------------------------------------------------

    Timeline timelineBuilder;
    IndicatorExtractor indicatorExtractor;
    IndicatorEnricher enricher;
    RiskScorer riskScorer;
    MitreMapper mitreMapper;

    nlohmann::json investigationResults =
        nlohmann::json::array();

    // --------------------------------------------------
    // PROCESS EACH INCIDENT
    // --------------------------------------------------

    for (const Incident& incident : incidents)
    {
        incident.display();

        // ----------------------------------------------
        // INDICATOR EXTRACTION
        // ----------------------------------------------

        std::vector<Indicator> indicators =
            indicatorExtractor.extract(
                incident,
                events
            );

        // ----------------------------------------------
        // INDICATOR ENRICHMENT
        // ----------------------------------------------

        for (Indicator& indicator : indicators)
        {
            enricher.enrich(indicator);
        }

        // ----------------------------------------------
        // RISK ASSESSMENT
        // ----------------------------------------------

        RiskAssessment risk =
            riskScorer.calculate(
                incident,
                indicators
            );

        std::cout
            << "\n=== RISK ASSESSMENT ===\n";

        std::cout
            << "Risk Score: "
            << risk.score
            << "/100\n";

        std::cout
            << "Risk Level: "
            << risk.level
            << '\n';

        std::cout << "Reasons:\n";

        for (const std::string& reason : risk.reasons)
        {
            std::cout
                << "- "
                << reason
                << '\n';
        }

        // ----------------------------------------------
        // MITRE ATT&CK MAPPING
        // ----------------------------------------------

        std::vector<MitreMapping> mitreMappings =
            mitreMapper.map(incident);

        std::cout
            << "\n=== MITRE ATT&CK MAPPING ===\n";

        if (mitreMappings.empty())
        {
            std::cout
                << "No supported MITRE ATT&CK mappings.\n";
        }

        for (const MitreMapping& mapping : mitreMappings)
        {
            std::cout
                << "Technique ID: "
                << mapping.techniqueId
                << '\n';

            std::cout
                << "Technique: "
                << mapping.techniqueName
                << '\n';

            std::cout
                << "Tactic: "
                << mapping.tactic
                << '\n';

            std::cout
                << "Confidence: "
                << mapping.confidence
                << '\n';

            std::cout
                << "Reason: "
                << mapping.reason
                << "\n\n";
        }

        // ----------------------------------------------
        // INDICATORS
        // ----------------------------------------------

        std::cout
            << "=== INDICATORS ===\n";

        if (indicators.empty())
        {
            std::cout
                << "No indicators extracted.\n";
        }

        for (const Indicator& indicator : indicators)
        {
            std::cout
                << "Type: "
                << indicator.type
                << '\n';

            std::cout
                << "Value: "
                << indicator.value
                << '\n';

            std::cout
                << "Source: "
                << indicator.source
                << '\n';

            std::cout
                << "Reputation: "
                << indicator.reputation
                << '\n';

            std::cout
                << "Confidence: "
                << indicator.confidence
                << '\n';

            std::cout
                << "Context: "
                << indicator.context
                << "\n\n";
        }

        // ----------------------------------------------
        // TIMELINE
        // ----------------------------------------------

        std::vector<TimelineEntry> timeline =
            timelineBuilder.build(
                incident,
                events
            );

        timelineBuilder.display(timeline);

        nlohmann::json timelineJson =
            timelineBuilder.toJson(timeline);

        std::cout
            << "\n=== TIMELINE JSON ===\n"
            << timelineJson.dump(4)
            << '\n';

        // ----------------------------------------------
        // INVESTIGATION JSON
        // ----------------------------------------------

        nlohmann::json incidentResult;

        incidentResult["incident_id"] =
            incident.incidentId;

        incidentResult["username"] =
            incident.username;

        incidentResult["source_ip"] =
            incident.sourceIp;

        incidentResult["hostname"] =
            incident.hostname;

        incidentResult["severity"] =
            incident.severity;

        incidentResult["risk_score"] =
            risk.score;

        incidentResult["risk_level"] =
            risk.level;

        incidentResult["risk_reasons"] =
            risk.reasons;

        incidentResult["timeline"] =
            timelineJson;

        

           nlohmann::json indicatorsJson =
        nlohmann::json::array();

    for (const Indicator& indicator : indicators)
    {
        nlohmann::json indicatorJson;

        indicatorJson["type"] =
            indicator.type;

        indicatorJson["value"] =
            indicator.value;

        indicatorJson["source"] =
            indicator.source;

        indicatorJson["reputation"] =
            indicator.reputation;

        indicatorJson["confidence"] =
            indicator.confidence;

        indicatorJson["context"] =
            indicator.context;

        indicatorsJson.push_back(indicatorJson);
    }

    incidentResult["indicators"] =
        indicatorsJson;

        nlohmann::json mitreJson =
            nlohmann::json::array();

        for (const MitreMapping& mapping : mitreMappings)
        {
            nlohmann::json mappingJson;

            mappingJson["technique_id"] =
                mapping.techniqueId;

            mappingJson["technique_name"] =
                mapping.techniqueName;

            mappingJson["tactic"] =
                mapping.tactic;

            mappingJson["confidence"] =
                mapping.confidence;

            mappingJson["reason"] =
                mapping.reason;

            mitreJson.push_back(mappingJson);
        }

        incidentResult["mitre_attack"] =
            mitreJson;

        investigationResults.push_back(
            incidentResult
        );
    }

    // --------------------------------------------------
    // COMPLETE
    // --------------------------------------------------

    std::cout
        << "\n=== INVESTIGATION COMPLETE ===\n";

    std::cout
        << "Processed "
        << incidents.size()
        << " incident(s).\n";

// --------------------------------------------------
// EXPORT INVESTIGATION RESULTS
// --------------------------------------------------

std::ofstream outputFile("investigation_results.json");

if (outputFile.is_open())
{
    outputFile << investigationResults.dump(4);
    outputFile.close();

    std::cout
        << "Investigation results exported to "
        << "investigation_results.json\n";
}
else
{
    std::cerr
        << "Failed to create investigation_results.json\n";
}

    return 0;
}