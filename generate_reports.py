"""Report generator for XYZ inventory data from CSV files."""
from __future__ import annotations

import csv
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Configure logging
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("cm.reports")


@dataclass
class DomainInfo:
    """Information about a domain."""
    domain_id: str
    name: str
    parent_domain_id: Optional[str]
    level: int
    children: List['DomainInfo'] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    state_info: Dict[str, Dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))


@dataclass
class InventoryStats:
    """Inventory statistics."""
    domains: int = 0
    users: int = 0
    users_in_groups: int = 0
    users_no_groups: int = 0
    groups: int = 0
    keys: int = 0
    quorum_profiles: int = 0
    quorum_policies_active: int = 0
    quorum_policies_inactive: int = 0
    policy_attachments: int = 0


class ReportGenerator:
    """Generates inventory and health-check reports from CSV files."""
    
    def __init__(self, output_dir: Path = Path("output")):
        self.output_dir = Path(output_dir)
        self.domains: Dict[str, DomainInfo] = {}
        self.domain_hierarchy: Dict[int, List[DomainInfo]] = defaultdict(list)
        
    def load_data(self):
        """Load all CSV files and build domain hierarchy."""
        logger.info("Loading data from CSV files...")
        
        # Load domain information
        self._load_domains()
        
        # Build domain hierarchy
        self._build_hierarchy()
        
        # Load all data and assign to domains
        self._load_users()
        self._load_groups()
        self._load_keys()
        self._load_quorum_data()
        self._load_policy_attachments()
        
        logger.info(f"Loaded data for {len(self.domains)} domains across {max(self.domain_hierarchy.keys()) if self.domain_hierarchy else 0} levels")
    
    def _load_domains(self):
        """Load domain information."""
        domain_file = self.output_dir / "domain.csv"
        if not domain_file.exists():
            logger.warning(f"Domain file not found: {domain_file}")
            return
        
        with open(domain_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain_id = row.get('id', '')
                if not domain_id:
                    continue
                    
                parent_id = row.get('parent_domain_id', '') or None
                # Treat root domain parent ID as None
                if parent_id in ('', '00000000-0000-0000-0000-000000000000', None):
                    parent_id = None
                
                domain = DomainInfo(
                    domain_id=domain_id,
                    name=row.get('name', 'unknown'),
                    parent_domain_id=parent_id,
                    level=0  # Will be set in _build_hierarchy
                )
                self.domains[domain_id] = domain
    
    def _build_hierarchy(self):
        """Build domain hierarchy and assign levels."""
        # Root domain ID (the special UUID for root)
        ROOT_DOMAIN_ID = "00000000-0000-0000-0000-000000000000"
        
        # Find root domain by ID or name
        root_domain = None
        for domain in self.domains.values():
            if domain.domain_id == ROOT_DOMAIN_ID or domain.name.lower() == "root":
                root_domain = domain
                break
        
        def assign_level(domain: DomainInfo, level: int):
            """Recursively assign levels and build hierarchy."""
            domain.level = level
            self.domain_hierarchy[level].append(domain)
            
            # Find children - either direct parent match or pointing to root UUID
            if domain.domain_id == ROOT_DOMAIN_ID:
                # Root domain: find all domains that point to root UUID as parent
                children = [d for d in self.domains.values() 
                           if d.parent_domain_id == ROOT_DOMAIN_ID 
                           and d.domain_id != ROOT_DOMAIN_ID]
            else:
                # Regular domain: find domains that have this as parent
                children = [d for d in self.domains.values() 
                           if d.parent_domain_id == domain.domain_id]
            
            domain.children = children
            
            # Recursively process children
            for child in children:
                assign_level(child, level + 1)
        
        # Start with root domain
        if root_domain:
            assign_level(root_domain, 1)
        else:
            # No explicit root found, treat domains with no parent or root UUID as level 1
            root_domains = [d for d in self.domains.values() 
                           if d.parent_domain_id is None 
                           or d.parent_domain_id == ROOT_DOMAIN_ID]
            for root in root_domains:
                if root.level == 0:  # Only assign if not already assigned
                    assign_level(root, 1)
        
        # Handle any remaining orphaned domains
        for domain in self.domains.values():
            if domain.level == 0:
                # Assign to level 2 as fallback
                domain.level = 2
                self.domain_hierarchy[2].append(domain)
    
    def _load_users(self):
        """Load user data."""
        # Load users in groups
        group_users_file = self.output_dir / "group_users.csv"
        if group_users_file.exists():
            with open(group_users_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain_id = row.get('logged_domain_id', '')
                    if domain_id in self.domains:
                        self.domains[domain_id].stats['users_in_groups'] += 1
                        self.domains[domain_id].stats['users_total'] += 1
                        
                        # Check user state
                        account_locked = bool(row.get('account_lockout_at', ''))
                        if account_locked:
                            self.domains[domain_id].state_info['users']['locked'] += 1
                        else:
                            self.domains[domain_id].state_info['users']['active'] += 1
                        
                        cert_auth = row.get('enable_cert_auth', '').lower() == 'true'
                        if cert_auth:
                            self.domains[domain_id].state_info['users']['cert_auth_enabled'] += 1
        
        # Load users not in groups
        no_group_users_file = self.output_dir / "no_group_users.csv"
        if no_group_users_file.exists():
            with open(no_group_users_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain_id = row.get('logged_domain_id', '')
                    if domain_id in self.domains:
                        self.domains[domain_id].stats['users_no_groups'] += 1
                        self.domains[domain_id].stats['users_total'] += 1
                        
                        # Check user state
                        account_locked = bool(row.get('account_lockout_at', ''))
                        if account_locked:
                            self.domains[domain_id].state_info['users']['locked'] += 1
                        else:
                            self.domains[domain_id].state_info['users']['active'] += 1
                        
                        cert_auth = row.get('enable_cert_auth', '').lower() == 'true'
                        if cert_auth:
                            self.domains[domain_id].state_info['users']['cert_auth_enabled'] += 1
    
    def _load_groups(self):
        """Load group data."""
        groups_file = self.output_dir / "groups.csv"
        if not groups_file.exists():
            return
        
        with open(groups_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain_id = row.get('logged_domain_id', '')
                if domain_id in self.domains:
                    self.domains[domain_id].stats['groups'] += 1
                    
                    # Check if group has users
                    users_count = row.get('users_count', '')
                    if users_count and users_count.strip():
                        try:
                            count = int(users_count)
                            if count > 0:
                                self.domains[domain_id].state_info['groups']['with_users'] += 1
                            else:
                                self.domains[domain_id].state_info['groups']['empty'] += 1
                        except ValueError:
                            pass
    
    def _load_keys(self):
        """Load key data."""
        keys_file = self.output_dir / "keys.csv"
        if not keys_file.exists():
            return
        
        with open(keys_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain_id = row.get('logged_domain_id', '')
                if domain_id in self.domains:
                    self.domains[domain_id].stats['keys'] += 1
                    
                    # Check key state
                    state = row.get('state', '').lower()
                    if state == 'active':
                        self.domains[domain_id].state_info['keys']['active'] += 1
                    elif state:
                        self.domains[domain_id].state_info['keys']['inactive'] += 1
                    
                    # Check exportability
                    never_export = row.get('neverExportable', '').lower() == 'true'
                    if never_export:
                        self.domains[domain_id].state_info['keys']['never_exportable'] += 1
    
    def _load_quorum_data(self):
        """Load quorum profiles and policy status."""
        # Load quorum profiles
        profiles_file = self.output_dir / "quorum_profiles.csv"
        if profiles_file.exists():
            with open(profiles_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain_id = row.get('logged_domain_id', '')
                    if domain_id in self.domains:
                        self.domains[domain_id].stats['quorum_profiles'] += 1
        
        # Load quorum policy status
        status_file = self.output_dir / "quorum_policy_status.csv"
        if status_file.exists():
            with open(status_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    domain_id = row.get('logged_domain_id', '')
                    if domain_id in self.domains:
                        active = row.get('active', '').lower() == 'true'
                        if active:
                            self.domains[domain_id].stats['quorum_policies_active'] += 1
                            self.domains[domain_id].state_info['quorum']['active'] += 1
                        else:
                            self.domains[domain_id].stats['quorum_policies_inactive'] += 1
                            self.domains[domain_id].state_info['quorum']['inactive'] += 1
    
    def _load_policy_attachments(self):
        """Load policy attachments."""
        policy_file = self.output_dir / "policy_attachments.csv"
        if not policy_file.exists():
            return
        
        with open(policy_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                domain_id = row.get('logged_domain_id', '')
                if domain_id in self.domains:
                    self.domains[domain_id].stats['policy_attachments'] += 1
                    
                    # Check policy effect
                    effect = row.get('effect', '').lower()
                    if effect == 'allow':
                        self.domains[domain_id].state_info['policies']['allow'] += 1
                    elif effect == 'deny':
                        self.domains[domain_id].state_info['policies']['deny'] += 1
    
    def generate_inventory_report(self) -> str:
        """Generate inventory report."""
        logger.info("Generating inventory report...")
        
        lines = []
        lines.append("=" * 80)
        lines.append("CTM INVENTORY REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        lines.append("")
        
        # Overall summary
        total_stats = InventoryStats()
        for domain in self.domains.values():
            total_stats.domains += 1
            total_stats.users += domain.stats.get('users_total', 0)
            total_stats.users_in_groups += domain.stats.get('users_in_groups', 0)
            total_stats.users_no_groups += domain.stats.get('users_no_groups', 0)
            total_stats.groups += domain.stats.get('groups', 0)
            total_stats.keys += domain.stats.get('keys', 0)
            total_stats.quorum_profiles += domain.stats.get('quorum_profiles', 0)
            total_stats.quorum_policies_active += domain.stats.get('quorum_policies_active', 0)
            total_stats.quorum_policies_inactive += domain.stats.get('quorum_policies_inactive', 0)
            total_stats.policy_attachments += domain.stats.get('policy_attachments', 0)
        
        lines.append("OVERALL SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Domains:            {total_stats.domains:>6}")
        lines.append(f"Total Users:              {total_stats.users:>6}")
        lines.append(f"  - In Groups:            {total_stats.users_in_groups:>6}")
        lines.append(f"  - Not in Groups:        {total_stats.users_no_groups:>6}")
        lines.append(f"Total Groups:             {total_stats.groups:>6}")
        lines.append(f"Total Keys:               {total_stats.keys:>6}")
        lines.append(f"Total Quorum Profiles:    {total_stats.quorum_profiles:>6}")
        lines.append(f"Total Quorum Policies:    {total_stats.quorum_policies_active + total_stats.quorum_policies_inactive:>6}")
        lines.append(f"  - Active:               {total_stats.quorum_policies_active:>6}")
        lines.append(f"  - Inactive:             {total_stats.quorum_policies_inactive:>6}")
        lines.append(f"Total Policy Attachments: {total_stats.policy_attachments:>6}")
        lines.append("")
        
        # Domain level breakdown
        for level in sorted(self.domain_hierarchy.keys()):
            domains_at_level = self.domain_hierarchy[level]
            if not domains_at_level:
                continue
            
            lines.append(f"LEVEL {level} DOMAINS ({len(domains_at_level)} domain(s))")
            lines.append("-" * 80)
            
            for domain in domains_at_level:
                indent = "  " * (level - 1)
                lines.append(f"{indent}[{domain.name}] (ID: {domain.domain_id[:8]}...)")
                
                stats = domain.stats
                lines.append(f"{indent}  Users:              {stats.get('users_total', 0):>4} (in groups: {stats.get('users_in_groups', 0)}, no groups: {stats.get('users_no_groups', 0)})")
                lines.append(f"{indent}  Groups:             {stats.get('groups', 0):>4}")
                lines.append(f"{indent}  Keys:               {stats.get('keys', 0):>4}")
                lines.append(f"{indent}  Quorum Profiles:    {stats.get('quorum_profiles', 0):>4}")
                lines.append(f"{indent}  Quorum Policies:    {stats.get('quorum_policies_active', 0) + stats.get('quorum_policies_inactive', 0):>4} (active: {stats.get('quorum_policies_active', 0)}, inactive: {stats.get('quorum_policies_inactive', 0)})")
                lines.append(f"{indent}  Policy Attachments: {stats.get('policy_attachments', 0):>4}")
                
                # Show children count
                if domain.children:
                    lines.append(f"{indent}  Subdomains:         {len(domain.children):>4}")
                
                lines.append("")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_health_check_report(self) -> str:
        """Generate health-check report."""
        logger.info("Generating health-check report...")
        
        lines = []
        lines.append("=" * 80)
        lines.append("CTM HEALTH-CHECK REPORT")
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        lines.append("")
        
        # Overall health summary
        total_issues = 0
        issues_by_type = defaultdict(int)
        
        for domain in self.domains.values():
            # User issues
            locked_users = domain.state_info.get('users', {}).get('locked', 0)
            if locked_users > 0:
                issues_by_type['locked_users'] += locked_users
                total_issues += locked_users
            
            # Key issues
            inactive_keys = domain.state_info.get('keys', {}).get('inactive', 0)
            if inactive_keys > 0:
                issues_by_type['inactive_keys'] += inactive_keys
                total_issues += inactive_keys
            
            # Quorum policy issues
            inactive_policies = domain.state_info.get('quorum', {}).get('inactive', 0)
            if inactive_policies > 0:
                issues_by_type['inactive_quorum_policies'] += inactive_policies
                total_issues += inactive_policies
        
        lines.append("HEALTH SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Issues Found: {total_issues}")
        if issues_by_type:
            for issue_type, count in sorted(issues_by_type.items()):
                lines.append(f"  - {issue_type.replace('_', ' ').title()}: {count}")
        else:
            lines.append("  No issues detected")
        lines.append("")
        
        # Domain level health check
        for level in sorted(self.domain_hierarchy.keys()):
            domains_at_level = self.domain_hierarchy[level]
            if not domains_at_level:
                continue
            
            lines.append(f"LEVEL {level} DOMAIN HEALTH ({len(domains_at_level)} domain(s))")
            lines.append("-" * 80)
            
            for domain in domains_at_level:
                indent = "  " * (level - 1)
                lines.append(f"{indent}[{domain.name}] (ID: {domain.domain_id[:8]}...)")
                
                # User health
                user_states = domain.state_info.get('users', {})
                active_users = user_states.get('active', 0)
                locked_users = user_states.get('locked', 0)
                cert_auth_users = user_states.get('cert_auth_enabled', 0)
                
                if locked_users > 0:
                    lines.append(f"{indent}  [WARN] USERS: {locked_users} locked account(s)")
                else:
                    lines.append(f"{indent}  [OK] USERS: {active_users} active ({cert_auth_users} with cert auth)")
                
                # Group health
                group_states = domain.state_info.get('groups', {})
                groups_with_users = group_states.get('with_users', 0)
                empty_groups = group_states.get('empty', 0)
                
                total_groups = domain.stats.get('groups', 0)
                if total_groups > 0:
                    lines.append(f"{indent}  [OK] GROUPS: {total_groups} total ({groups_with_users} with users, {empty_groups} empty)")
                
                # Key health
                key_states = domain.state_info.get('keys', {})
                active_keys = key_states.get('active', 0)
                inactive_keys = key_states.get('inactive', 0)
                never_exportable = key_states.get('never_exportable', 0)
                
                if inactive_keys > 0:
                    lines.append(f"{indent}  [WARN] KEYS: {inactive_keys} inactive key(s) found")
                if active_keys > 0:
                    lines.append(f"{indent}  [OK] KEYS: {active_keys} active ({never_exportable} never exportable)")
                
                # Quorum health
                quorum_states = domain.state_info.get('quorum', {})
                active_quorum = quorum_states.get('active', 0)
                inactive_quorum = quorum_states.get('inactive', 0)
                
                if inactive_quorum > 0:
                    lines.append(f"{indent}  [WARN] QUORUM: {inactive_quorum} inactive policy/policies")
                if active_quorum > 0:
                    lines.append(f"{indent}  [OK] QUORUM: {active_quorum} active policy/policies")
                
                # Policy health
                policy_states = domain.state_info.get('policies', {})
                allow_policies = policy_states.get('allow', 0)
                deny_policies = policy_states.get('deny', 0)
                
                total_policies = domain.stats.get('policy_attachments', 0)
                if total_policies > 0:
                    lines.append(f"{indent}  [OK] POLICIES: {total_policies} total ({allow_policies} allow, {deny_policies} deny)")
                
                lines.append("")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def generate_html_report(self) -> str:
        """Generate combined HTML report."""
        logger.info("Generating HTML report...")
        
        inventory = self.generate_inventory_report()
        health_check = self.generate_health_check_report()
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CTM Inventory & Health Check Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        pre {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            border-left: 4px solid #3498db;
            font-size: 12px;
            line-height: 1.6;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            text-align: center;
            font-size: 12px;
        }}
        .warning {{
            color: #e74c3c;
            font-weight: bold;
        }}
        .success {{
            color: #27ae60;
            font-weight: bold;
        }}
        .ok {{
            color: #27ae60;
        }}
        .warn {{
            color: #e74c3c;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>CTM Inventory & Health Check Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Inventory Report</h2>
        <pre>{inventory.replace('<', '&lt;').replace('>', '&gt;')}</pre>
        
        <h2>Health Check Report</h2>
        <pre>{health_check.replace('<', '&lt;').replace('>', '&gt;')}</pre>
        
        <div class="footer">
            Generated by CTM Inventory Report Generator
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def save_reports(self, output_dir: Path = Path("reports")):
        """Save all reports to files."""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save text reports
        inventory_text = self.generate_inventory_report()
        inventory_file = output_dir / f"inventory_report_{timestamp}.txt"
        with open(inventory_file, 'w', encoding='utf-8') as f:
            f.write(inventory_text)
        logger.info(f"Inventory report saved to: {inventory_file}")
        
        health_check_text = self.generate_health_check_report()
        health_check_file = output_dir / f"health_check_report_{timestamp}.txt"
        with open(health_check_file, 'w', encoding='utf-8') as f:
            f.write(health_check_text)
        logger.info(f"Health-check report saved to: {health_check_file}")
        
        # Save HTML report
        html_report = self.generate_html_report()
        html_file = output_dir / f"combined_report_{timestamp}.html"
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        logger.info(f"HTML report saved to: {html_file}")
        
        # Save JSON report
        json_report = self.generate_json_report()
        json_file = output_dir / f"report_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2)
        logger.info(f"JSON report saved to: {json_file}")
    
    def generate_json_report(self) -> dict:
        """Generate JSON report."""
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "domains": {}
        }
        
        # Calculate summary
        total_stats = InventoryStats()
        for domain in self.domains.values():
            total_stats.domains += 1
            total_stats.users += domain.stats.get('users_total', 0)
            total_stats.users_in_groups += domain.stats.get('users_in_groups', 0)
            total_stats.users_no_groups += domain.stats.get('users_no_groups', 0)
            total_stats.groups += domain.stats.get('groups', 0)
            total_stats.keys += domain.stats.get('keys', 0)
            total_stats.quorum_profiles += domain.stats.get('quorum_profiles', 0)
            total_stats.quorum_policies_active += domain.stats.get('quorum_policies_active', 0)
            total_stats.quorum_policies_inactive += domain.stats.get('quorum_policies_inactive', 0)
            total_stats.policy_attachments += domain.stats.get('policy_attachments', 0)
        
        report["summary"] = {
            "domains": total_stats.domains,
            "users": {
                "total": total_stats.users,
                "in_groups": total_stats.users_in_groups,
                "no_groups": total_stats.users_no_groups
            },
            "groups": total_stats.groups,
            "keys": total_stats.keys,
            "quorum_profiles": total_stats.quorum_profiles,
            "quorum_policies": {
                "total": total_stats.quorum_policies_active + total_stats.quorum_policies_inactive,
                "active": total_stats.quorum_policies_active,
                "inactive": total_stats.quorum_policies_inactive
            },
            "policy_attachments": total_stats.policy_attachments
        }
        
        # Domain details
        for domain_id, domain in self.domains.items():
            report["domains"][domain_id] = {
                "name": domain.name,
                "level": domain.level,
                "parent_domain_id": domain.parent_domain_id,
                "stats": dict(domain.stats),
                "state_info": {
                    k: dict(v) for k, v in domain.state_info.items()
                },
                "children_count": len(domain.children)
            }
        
        return report
    
    def print_reports(self):
        """Print reports to console."""
        print("\n" + self.generate_inventory_report())
        print("\n" + self.generate_health_check_report())


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate CTM inventory and health-check reports")
    parser.add_argument("--output-dir", type=Path, default=Path("output"),
                       help="Directory containing CSV files (default: output)")
    parser.add_argument("--reports-dir", type=Path, default=Path("reports"),
                       help="Directory to save reports (default: reports)")
    parser.add_argument("--console", action="store_true",
                       help="Also print reports to console")
    parser.add_argument("--html-only", action="store_true",
                       help="Generate only HTML report")
    
    args = parser.parse_args()
    
    generator = ReportGenerator(output_dir=args.output_dir)
    
    try:
        generator.load_data()
        
        if args.html_only:
            html_report = generator.generate_html_report()
            reports_dir = Path(args.reports_dir)
            reports_dir.mkdir(exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_file = reports_dir / f"combined_report_{timestamp}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            logger.info(f"HTML report saved to: {html_file}")
        else:
            generator.save_reports(output_dir=args.reports_dir)
        
        if args.console:
            generator.print_reports()
        
        logger.info("Report generation completed successfully")
        
    except Exception as e:
        logger.error(f"Error generating reports: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

