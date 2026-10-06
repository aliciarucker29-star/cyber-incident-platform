cmake_minimum_required(VERSION 3.16)

project(InvestigationEngine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(
    investigation_engine
    src/main.cpp
    src/Event.cpp
    src/Detector.cpp
    src/EventLoader.cpp
    src/Incident.cpp
    src/Correlator.cpp
    src/Timeline.cpp
    src/IndicatorExtractor.cpp
    src/IndicatorEnricher.cpp
    src/RiskScorer.cpp
    src/MitreMapper.cpp
)

target_include_directories(
    investigation_engine
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)