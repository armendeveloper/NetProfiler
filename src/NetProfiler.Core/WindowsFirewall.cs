using System.Reflection;
using System.Runtime.InteropServices;

namespace NetProfiler.Core;

/// <summary>
/// Blocks and unblocks addresses with Windows Firewall rules (one inbound, one outbound per target)
/// through the built-in HNetCfg COM API. Reading works for any user; changes need administrator rights.
/// Rules persist after the app closes.
/// </summary>
public sealed class WindowsFirewall
{
    private const int ActionBlock = 0;
    private const int DirectionIn = 1;
    private const int DirectionOut = 2;
    private const int ProtocolAny = 256;
    private const int AllProfiles = 0x7FFFFFFF;

    public IReadOnlyList<BlockedRule> GetBlocked()
    {
        var found = new Dictionary<BlockTarget, (bool In, bool Out, string? Description)>();
        var policy = CreatePolicy();
        try
        {
            foreach (dynamic rule in policy.Rules)
            {
                string name = rule.Name ?? string.Empty;
                if (!FirewallRuleNames.TryParse(name, out var target, out var direction))
                    continue;
                string? grouping = rule.Grouping;
                if (grouping != FirewallRuleNames.Group || (int)rule.Action != ActionBlock || !(bool)rule.Enabled)
                    continue;

                var current = found.GetValueOrDefault(target);
                string? description = rule.Description;
                found[target] = direction == FirewallDirection.Inbound
                    ? (true, current.Out, current.Description ?? description)
                    : (current.In, true, current.Description ?? description);
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }

        return found
            .Select(pair => new BlockedRule(pair.Key, pair.Value.In, pair.Value.Out, pair.Value.Description))
            .OrderBy(rule => rule.Target.ToString(), StringComparer.Ordinal)
            .ToList();
    }

    public FirewallState GetState()
    {
        var policy = CreatePolicy();
        try
        {
            int current = policy.CurrentProfileTypes;
            var active = new List<string>();
            var allEnabled = true;
            foreach (var (bit, label) in new[] { (1, "Domain"), (2, "Private"), (4, "Public") })
            {
                if ((current & bit) == 0)
                    continue;
                active.Add(label);
                // FirewallEnabled is an indexed COM property, which dynamic can't call directly.
                var enabled = ((object)policy).GetType().InvokeMember(
                    "FirewallEnabled", BindingFlags.GetProperty, null, (object)policy, [bit]);
                allEnabled &= enabled is true;
            }
            return new FirewallState(active, allEnabled);
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }
    }

    public void Block(BlockTarget target)
    {
        var policy = CreatePolicy();
        try
        {
            RemoveRules(policy, target);
            var stamp = $"Blocked by NetProfiler on {DateTime.Now:yyyy-MM-dd HH:mm}";
            try
            {
                foreach (var direction in new[] { FirewallDirection.Inbound, FirewallDirection.Outbound })
                {
                    dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!)!;
                    rule.Name = FirewallRuleNames.For(target, direction);
                    rule.Description = stamp;
                    rule.Grouping = FirewallRuleNames.Group;
                    rule.Protocol = ProtocolAny;
                    rule.RemoteAddresses = target.ToString();
                    rule.Direction = direction == FirewallDirection.Inbound ? DirectionIn : DirectionOut;
                    rule.Action = ActionBlock;
                    rule.Profiles = AllProfiles;
                    rule.Enabled = true;
                    policy.Rules.Add(rule);
                }
            }
            catch
            {
                // Never leave a half block (inbound only) behind: undo what was added, then report the error.
                try
                {
                    RemoveRules(policy, target);
                }
                catch (Exception)
                {
                    // Keep the original error; it is the one worth showing.
                }
                throw;
            }
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }
    }

    public void Unblock(BlockTarget target)
    {
        var policy = CreatePolicy();
        try
        {
            RemoveRules(policy, target);
        }
        finally
        {
            Marshal.FinalReleaseComObject(policy);
        }
    }

    private static void RemoveRules(dynamic policy, BlockTarget target)
    {
        foreach (var direction in new[] { FirewallDirection.Inbound, FirewallDirection.Outbound })
        {
            var name = FirewallRuleNames.For(target, direction);
            // Remove deletes one rule per call; loop in case duplicates were created by hand.
            for (var i = 0; i < 16 && RuleExists(policy, name); i++)
                policy.Rules.Remove(name);
        }
    }

    private const int ErrorFileNotFound = unchecked((int)0x80070002);

    private static bool RuleExists(dynamic policy, string name)
    {
        try
        {
            var rule = policy.Rules.Item(name);
            return rule is not null;
        }
        // Only "no such rule" means absent. Anything else (firewall service down, RPC failure) must
        // surface, or Unblock would report success without removing anything.
        catch (Exception ex) when (ex.HResult == ErrorFileNotFound)
        {
            return false;
        }
    }

    private static dynamic CreatePolicy() =>
        Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!)!;
}
