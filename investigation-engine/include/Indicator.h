#ifndef INDICATOR_H
#define INDICATOR_H

#include <string>

struct Indicator
{
std::string type;
std::string value;
std::string source;
std::string reputation;
std::string context;
int confidence;
};

#endif