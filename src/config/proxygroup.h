#ifndef PROXYGROUP_H_INCLUDED
#define PROXYGROUP_H_INCLUDED

#include "def.h"

enum class ProxyGroupType
{
    Select,
    URLTest,
    Fallback,
    LoadBalance,
    Relay,
    SSID,
    Smart
};

enum class BalanceStrategy
{
    ConsistentHashing,
    RoundRobin
};

struct ProxyGroupConfig
{
    String Name;
    ProxyGroupType Type;
    StrArray Proxies;
    StrArray UsingProvider;
    String Url;
    Integer Interval = 0;
    Integer Timeout = 0;
    Integer Tolerance = 0;
    BalanceStrategy Strategy = BalanceStrategy::ConsistentHashing;
    Boolean Lazy;
    Boolean DisableUdp;
    Boolean Persistent;
    Boolean EvaluateBeforeUse;
    string_map Extras;

    String TypeStr() const
    {
        switch(Type)
        {
            case ProxyGroupType::Select: return "select";
            case ProxyGroupType::URLTest: return "url-test";
            case ProxyGroupType::LoadBalance: return "load-balance";
            case ProxyGroupType::Fallback: return "fallback";
            case ProxyGroupType::Relay: return "relay";
            case ProxyGroupType::SSID: return "ssid";
            case ProxyGroupType::Smart: return "smart";
        }
        return "";
    }

    String StrategyStr() const
    {
        switch(Strategy)
        {
            case BalanceStrategy::ConsistentHashing: return "consistent-hashing";
            case BalanceStrategy::RoundRobin: return "round-robin";
        }
        return "";
    }
};

using ProxyGroupConfigs = std::vector<ProxyGroupConfig>;

// The "!!" prefix is shared by two features: node-matching directives handled by
// applyMatcher() in generator/config/subexport.cpp (e.g. "!!GROUP=tag",
// "!!GROUPID=0!!(regex)", plus "!!PROVIDER=" consumed during INI parsing) and
// arbitrary Clash group extras (e.g. "!!lazy=true"). Matching directives must
// always stay in the rule list, otherwise groups such as `g`select`!!GROUPID=0`
// would match no nodes. Keep this list in sync with applyMatcher().
inline bool isProxyGroupMatcherDirective(const String &rule)
{
    static const StrArray prefixes = {
        "!!GROUP=", "!!GROUPID=", "!!INSERT=", "!!TYPE=", "!!PORT=", "!!SERVER=", "!!PROVIDER="
    };
    for(const String &prefix : prefixes)
        if(startsWith(rule, prefix))
            return true;
    return false;
}

#endif // PROXYGROUP_H_INCLUDED
