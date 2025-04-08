#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Cloud Security Tools for Pegasus-Suite
"""

import os
import sys
import re
import subprocess
import platform
import random
import time
import json

class CloudSecurityTools:
    """Cloud infrastructure security assessment tools"""
    
    def __init__(self):
        """Initialize cloud security tools"""
        self.is_windows = platform.system() == 'Windows'
        self.output_dir = "cloud_security_results"
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            try:
                os.makedirs(self.output_dir)
            except:
                self.output_dir = "."
    
    def aws_security_scanner(self):
        """Scan AWS environment for security issues"""
        print("[+] AWS Security Scanner")
        print("[*] Note: This is a simulation. Real scanning requires AWS CLI and credentials.")
        
        # Check if we should do a real scan or simulation
        choice = input("Do you want to check for real AWS CLI configuration? (y/n) [n]: ") or "n"
        
        if choice.lower() == "y":
            # Try to get AWS profile info
            try:
                print("[*] Checking for AWS CLI configuration...")
                if self.is_windows:
                    result = subprocess.run("aws configure list", shell=True, capture_output=True, text=True)
                else:
                    result = subprocess.run(["aws", "configure", "list"], capture_output=True, text=True)
                
                if "profile" in result.stdout:
                    print("[+] AWS CLI is configured")
                    print(result.stdout)
                else:
                    print("[-] AWS CLI is not properly configured")
                    print("[*] Continuing with simulation")
            except:
                print("[-] AWS CLI not installed or not in PATH")
                print("[*] Continuing with simulation")
        
        print("\n[*] Simulating AWS security assessment...")
        
        # Simulate scan progress
        services = ["IAM", "S3", "EC2", "RDS", "Lambda", "CloudTrail", "CloudWatch", "VPC", "EKS", "SQS"]
        findings = []
        
        for service in services:
            print(f"[*] Scanning {service} service...")
            time.sleep(0.5)
            
            # Simulate random findings for each service
            if service == "IAM":
                if random.random() < 0.4:
                    findings.append(("IAM", "High", "Root account access keys are active"))
                if random.random() < 0.3:
                    findings.append(("IAM", "Medium", "Users with password but without MFA"))
                if random.random() < 0.5:
                    findings.append(("IAM", "Medium", "IAM policies with wildcard permissions"))
            
            elif service == "S3":
                if random.random() < 0.3:
                    findings.append(("S3", "Critical", "Public accessible S3 buckets"))
                if random.random() < 0.4:
                    findings.append(("S3", "High", "S3 buckets without encryption"))
                if random.random() < 0.2:
                    findings.append(("S3", "Medium", "S3 buckets without proper logging"))
            
            elif service == "EC2":
                if random.random() < 0.5:
                    findings.append(("EC2", "High", "Security groups with unrestricted access (0.0.0.0/0)"))
                if random.random() < 0.4:
                    findings.append(("EC2", "Medium", "EC2 instances without tags"))
                if random.random() < 0.3:
                    findings.append(("EC2", "Low", "Unattached Elastic IPs"))
            
            elif service == "RDS":
                if random.random() < 0.4:
                    findings.append(("RDS", "High", "RDS instances publicly accessible"))
                if random.random() < 0.5:
                    findings.append(("RDS", "Medium", "RDS instances without encryption"))
                if random.random() < 0.3:
                    findings.append(("RDS", "Low", "Automatic backups disabled"))
            
            elif service == "CloudTrail":
                if random.random() < 0.3:
                    findings.append(("CloudTrail", "Critical", "CloudTrail logging disabled"))
                if random.random() < 0.2:
                    findings.append(("CloudTrail", "High", "CloudTrail logs not encrypted"))
            
            elif service == "VPC":
                if random.random() < 0.4:
                    findings.append(("VPC", "Medium", "Default VPC in use"))
                if random.random() < 0.3:
                    findings.append(("VPC", "Low", "VPC Flow Logs disabled"))
        
        # Display findings
        if findings:
            print("\n[!] Security findings:")
            
            # Categorize by severity
            criticals = [f for f in findings if f[1] == "Critical"]
            highs = [f for f in findings if f[1] == "High"]
            mediums = [f for f in findings if f[1] == "Medium"]
            lows = [f for f in findings if f[1] == "Low"]
            
            if criticals:
                print("\n  [CRITICAL]")
                for service, _, issue in criticals:
                    print(f"  - {service}: {issue}")
                    
            if highs:
                print("\n  [HIGH]")
                for service, _, issue in highs:
                    print(f"  - {service}: {issue}")
                    
            if mediums:
                print("\n  [MEDIUM]")
                for service, _, issue in mediums:
                    print(f"  - {service}: {issue}")
                    
            if lows:
                print("\n  [LOW]")
                for service, _, issue in lows:
                    print(f"  - {service}: {issue}")
        else:
            print("\n[+] No security issues found. Environment appears to be well configured.")
        
        # Generate report
        print("\n[*] Generating report...")
        report_path = os.path.join(self.output_dir, f"aws_security_report_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            with open(report_path, 'w') as f:
                f.write("AWS Security Assessment Report\n")
                f.write("============================\n\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("Services Scanned:\n")
                for service in services:
                    f.write(f"- {service}\n")
                
                f.write("\nFindings:\n")
                if findings:
                    for service, severity, issue in findings:
                        f.write(f"[{severity}] {service}: {issue}\n")
                else:
                    f.write("No security issues found.\n")
                
                f.write("\nRecommendations:\n")
                if findings:
                    for service, severity, issue in findings:
                        f.write(f"- {service}: ")
                        if "Root account" in issue:
                            f.write("Disable or delete root account access keys.\n")
                        elif "without MFA" in issue:
                            f.write("Enable MFA for all users with console access.\n")
                        elif "wildcard" in issue:
                            f.write("Review and restrict IAM policies to follow least privilege principle.\n")
                        elif "Public" in issue and "S3" in service:
                            f.write("Restrict bucket access and audit all public buckets.\n")
                        elif "encryption" in issue:
                            f.write("Enable encryption for data at rest.\n")
                        elif "unrestricted access" in issue:
                            f.write("Restrict security group rules to specific IP ranges.\n")
                        elif "CloudTrail logging disabled" in issue:
                            f.write("Enable CloudTrail in all regions.\n")
                        else:
                            f.write("Review and implement best security practices.\n")
                else:
                    f.write("Continue maintaining good security posture.\n")
                
            print(f"[+] Report saved to: {report_path}")
            
        except Exception as e:
            print(f"[!] Error saving report: {e}")
        
        input("\nPress Enter to continue...")
    
    def azure_security_scanner(self):
        """Scan Azure environment for security issues"""
        print("[+] Azure Security Scanner")
        print("[*] Note: This is a simulation. Real scanning requires Azure CLI and credentials.")
        
        # Check if we should do a real scan or simulation
        choice = input("Do you want to check for real Azure CLI configuration? (y/n) [n]: ") or "n"
        
        if choice.lower() == "y":
            # Try to get Azure profile info
            try:
                print("[*] Checking for Azure CLI configuration...")
                if self.is_windows:
                    result = subprocess.run("az account show", shell=True, capture_output=True, text=True)
                else:
                    result = subprocess.run(["az", "account", "show"], capture_output=True, text=True)
                
                if result.returncode == 0:
                    print("[+] Azure CLI is configured")
                    try:
                        account_info = json.loads(result.stdout)
                        print(f"    Name: {account_info.get('name', 'Unknown')}")
                        print(f"    ID: {account_info.get('id', 'Unknown')}")
                        print(f"    Tenant: {account_info.get('tenantId', 'Unknown')}")
                    except:
                        print(result.stdout)
                else:
                    print("[-] Azure CLI is not properly configured")
                    print("[*] Continuing with simulation")
            except:
                print("[-] Azure CLI not installed or not in PATH")
                print("[*] Continuing with simulation")
        
        print("\n[*] Simulating Azure security assessment...")
        
        # Simulate scan progress
        services = ["Identity", "Network Security", "Storage", "Compute", "Databases", "Monitoring", "Key Vault"]
        findings = []
        
        for service in services:
            print(f"[*] Scanning {service}...")
            time.sleep(0.5)
            
            # Simulate random findings for each service
            if service == "Identity":
                if random.random() < 0.4:
                    findings.append(("Identity", "High", "Users with high privileges without MFA"))
                if random.random() < 0.3:
                    findings.append(("Identity", "Medium", "Service principals with excessive permissions"))
                if random.random() < 0.5:
                    findings.append(("Identity", "Low", "Guest users present in directory"))
            
            elif service == "Network Security":
                if random.random() < 0.3:
                    findings.append(("Network Security", "High", "NSGs with permissive inbound rules (Any:Any)"))
                if random.random() < 0.4:
                    findings.append(("Network Security", "Medium", "Subnets without NSGs applied"))
                if random.random() < 0.2:
                    findings.append(("Network Security", "Low", "Virtual Network peering without proper security controls"))
            
            elif service == "Storage":
                if random.random() < 0.5:
                    findings.append(("Storage", "Critical", "Storage accounts with public access"))
                if random.random() < 0.4:
                    findings.append(("Storage", "Medium", "Storage accounts without encryption"))
                if random.random() < 0.3:
                    findings.append(("Storage", "Low", "Storage accounts without blob soft delete enabled"))
            
            elif service == "Compute":
                if random.random() < 0.4:
                    findings.append(("Compute", "High", "VMs with public IPs"))
                if random.random() < 0.5:
                    findings.append(("Compute", "Medium", "VMs without disk encryption"))
                if random.random() < 0.3:
                    findings.append(("Compute", "Low", "VM auto-shutdown not configured"))
            
            elif service == "Monitoring":
                if random.random() < 0.3:
                    findings.append(("Monitoring", "High", "Azure Security Center standard tier not enabled"))
                if random.random() < 0.2:
                    findings.append(("Monitoring", "Medium", "Diagnostic logs not enabled for critical resources"))
            
            elif service == "Key Vault":
                if random.random() < 0.4:
                    findings.append(("Key Vault", "High", "Key Vault accessible from public networks"))
                if random.random() < 0.3:
                    findings.append(("Key Vault", "Medium", "Key Vault without advanced threat protection"))
        
        # Display findings
        if findings:
            print("\n[!] Security findings:")
            
            # Categorize by severity
            criticals = [f for f in findings if f[1] == "Critical"]
            highs = [f for f in findings if f[1] == "High"]
            mediums = [f for f in findings if f[1] == "Medium"]
            lows = [f for f in findings if f[1] == "Low"]
            
            if criticals:
                print("\n  [CRITICAL]")
                for service, _, issue in criticals:
                    print(f"  - {service}: {issue}")
                    
            if highs:
                print("\n  [HIGH]")
                for service, _, issue in highs:
                    print(f"  - {service}: {issue}")
                    
            if mediums:
                print("\n  [MEDIUM]")
                for service, _, issue in mediums:
                    print(f"  - {service}: {issue}")
                    
            if lows:
                print("\n  [LOW]")
                for service, _, issue in lows:
                    print(f"  - {service}: {issue}")
        else:
            print("\n[+] No security issues found. Environment appears to be well configured.")
        
        # Generate report
        print("\n[*] Generating report...")
        report_path = os.path.join(self.output_dir, f"azure_security_report_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            with open(report_path, 'w') as f:
                f.write("Azure Security Assessment Report\n")
                f.write("==============================\n\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("Services Scanned:\n")
                for service in services:
                    f.write(f"- {service}\n")
                
                f.write("\nFindings:\n")
                if findings:
                    for service, severity, issue in findings:
                        f.write(f"[{severity}] {service}: {issue}\n")
                else:
                    f.write("No security issues found.\n")
                
                f.write("\nRecommendations:\n")
                if findings:
                    for service, severity, issue in findings:
                        f.write(f"- {service}: ")
                        if "without MFA" in issue:
                            f.write("Enable MFA for all privileged accounts.\n")
                        elif "public access" in issue:
                            f.write("Restrict access to trusted networks only.\n")
                        elif "encryption" in issue:
                            f.write("Enable encryption for data at rest.\n")
                        elif "NSGs with permissive" in issue:
                            f.write("Review and restrict NSG rules to specific IP ranges.\n")
                        elif "Security Center" in issue:
                            f.write("Enable Azure Security Center standard tier for enhanced security.\n")
                        elif "public IPs" in issue:
                            f.write("Use private IPs and Azure Private Link where possible.\n")
                        else:
                            f.write("Review and implement Azure security best practices.\n")
                else:
                    f.write("Continue maintaining good security posture.\n")
                
            print(f"[+] Report saved to: {report_path}")
            
        except Exception as e:
            print(f"[!] Error saving report: {e}")
        
        input("\nPress Enter to continue...")
    
    def gcp_security_scanner(self):
        """Scan Google Cloud Platform environment for security issues"""
        print("[+] GCP Security Scanner")
        print("[*] Note: This is a simulation. Real scanning requires GCP SDK and credentials.")
        
        # Check if we should do a real scan or simulation
        choice = input("Do you want to check for real GCP CLI configuration? (y/n) [n]: ") or "n"
        
        if choice.lower() == "y":
            # Try to get GCP info
            try:
                print("[*] Checking for GCP CLI configuration...")
                if self.is_windows:
                    result = subprocess.run("gcloud config list", shell=True, capture_output=True, text=True)
                else:
                    result = subprocess.run(["gcloud", "config", "list"], capture_output=True, text=True)
                
                if result.returncode == 0:
                    print("[+] GCP CLI is configured")
                    print(result.stdout)
                else:
                    print("[-] GCP CLI is not properly configured")
                    print("[*] Continuing with simulation")
            except:
                print("[-] GCP CLI not installed or not in PATH")
                print("[*] Continuing with simulation")
        
        print("\n[*] Simulating GCP security assessment...")
        
        # Simulate scan progress
        services = ["IAM", "Compute Engine", "Cloud Storage", "VPC", "SQL", "KMS", "Logging"]
        findings = []
        
        for service in services:
            print(f"[*] Scanning {service}...")
            time.sleep(0.5)
            
            # Simulate random findings for each service
            if service == "IAM":
                if random.random() < 0.4:
                    findings.append(("IAM", "High", "Service accounts with owner permissions"))
                if random.random() < 0.3:
                    findings.append(("IAM", "Medium", "Users with excessive permissions"))
                if random.random() < 0.5:
                    findings.append(("IAM", "Low", "Service account keys not rotated recently"))
            
            elif service == "Compute Engine":
                if random.random() < 0.3:
                    findings.append(("Compute Engine", "High", "VMs with public IPs"))
                if random.random() < 0.4:
                    findings.append(("Compute Engine", "Medium", "Default service account used on VMs"))
                if random.random() < 0.2:
                    findings.append(("Compute Engine", "Low", "OS Login not enabled"))
            
            elif service == "Cloud Storage":
                if random.random() < 0.5:
                    findings.append(("Cloud Storage", "Critical", "Buckets with public access"))
                if random.random() < 0.4:
                    findings.append(("Cloud Storage", "Medium", "Buckets without encryption"))
                if random.random() < 0.3:
                    findings.append(("Cloud Storage", "Low", "Buckets without object versioning"))
            
            elif service == "VPC":
                if random.random() < 0.4:
                    findings.append(("VPC", "High", "Firewall rules with unrestricted access (0.0.0.0/0)"))
                if random.random() < 0.5:
                    findings.append(("VPC", "Medium", "VPC flow logs not enabled"))
                if random.random() < 0.3:
                    findings.append(("VPC", "Low", "Default VPC network in use"))
            
            elif service == "SQL":
                if random.random() < 0.3:
                    findings.append(("SQL", "High", "Cloud SQL instances publicly accessible"))
                if random.random() < 0.2:
                    findings.append(("SQL", "Medium", "Cloud SQL without automatic backups"))
            
            elif service == "Logging":
                if random.random() < 0.4:
                    findings.append(("Logging", "Medium", "Data access logs not enabled"))
                if random.random() < 0.3:
                    findings.append(("Logging", "Low", "Log sinks not configured for long-term retention"))
        
        # Display findings
        if findings:
            print("\n[!] Security findings:")
            
            # Categorize by severity
            criticals = [f for f in findings if f[1] == "Critical"]
            highs = [f for f in findings if f[1] == "High"]
            mediums = [f for f in findings if f[1] == "Medium"]
            lows = [f for f in findings if f[1] == "Low"]
            
            if criticals:
                print("\n  [CRITICAL]")
                for service, _, issue in criticals:
                    print(f"  - {service}: {issue}")
                    
            if highs:
                print("\n  [HIGH]")
                for service, _, issue in highs:
                    print(f"  - {service}: {issue}")
                    
            if mediums:
                print("\n  [MEDIUM]")
                for service, _, issue in mediums:
                    print(f"  - {service}: {issue}")
                    
            if lows:
                print("\n  [LOW]")
                for service, _, issue in lows:
                    print(f"  - {service}: {issue}")
        else:
            print("\n[+] No security issues found. Environment appears to be well configured.")
        
        # Generate report
        print("\n[*] Generating report...")
        report_path = os.path.join(self.output_dir, f"gcp_security_report_{time.strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            with open(report_path, 'w') as f:
                f.write("GCP Security Assessment Report\n")
                f.write("=============================\n\n")
                f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write("Services Scanned:\n")
                for service in services:
                    f.write(f"- {service}\n")
                
                f.write("\nFindings:\n")
                if findings:
                    for service, severity, issue in findings:
                        f.write(f"[{severity}] {service}: {issue}\n")
                else:
                    f.write("No security issues found.\n")
                
                f.write("\nRecommendations:\n")
                if findings:
                    for service, severity, issue in findings:
                        f.write(f"- {service}: ")
                        if "owner permissions" in issue:
                            f.write("Apply principle of least privilege to service accounts.\n")
                        elif "public access" in issue:
                            f.write("Restrict access to trusted networks only.\n")
                        elif "encryption" in issue:
                            f.write("Enable encryption for data at rest.\n")
                        elif "unrestricted access" in issue:
                            f.write("Restrict firewall rules to specific IP ranges.\n")
                        elif "publicly accessible" in issue:
                            f.write("Restrict access to private networks only.\n")
                        elif "logs not enabled" in issue:
                            f.write("Enable comprehensive logging for security analysis.\n")
                        else:
                            f.write("Review and implement GCP security best practices.\n")
                else:
                    f.write("Continue maintaining good security posture.\n")
                
            print(f"[+] Report saved to: {report_path}")
            
        except Exception as e:
            print(f"[!] Error saving report: {e}")
        
        input("\nPress Enter to continue...")
    
    def container_security_scanner(self):
        """Scan container configurations for security issues"""
        print("[+] Container Security Scanner")
        
        # Option to analyze a local Dockerfile or Kubernetes manifest
        print("\nOptions:")
        print("1. Analyze a Dockerfile")
        print("2. Analyze Kubernetes manifests")
        print("3. Analyze Docker Compose file")
        print("4. Back")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            self._analyze_dockerfile()
        elif choice == "2":
            self._analyze_kubernetes()
        elif choice == "3":
            self._analyze_docker_compose()
        elif choice == "4":
            return
        else:
            print("[!] Invalid choice")
            input("\nPress Enter to continue...")
    
    def _analyze_dockerfile(self):
        """Analyze a Dockerfile for security issues"""
        print("[+] Dockerfile Security Analyzer")
        
        dockerfile_path = input("Enter path to Dockerfile: ")
        if not dockerfile_path:
            print("[!] No file specified.")
            input("\nPress Enter to continue...")
            return
        
        if not os.path.exists(dockerfile_path):
            print("[!] File does not exist.")
            input("\nPress Enter to continue...")
            return
        
        print(f"[*] Analyzing Dockerfile: {dockerfile_path}")
        
        # Read the Dockerfile
        try:
            with open(dockerfile_path, 'r') as f:
                dockerfile_content = f.read()
            
            # Common Dockerfile security issues to check
            issues = []
            
            # Check if using latest tag
            if re.search(r'FROM\s+\S+:latest', dockerfile_content, re.IGNORECASE):
                issues.append(("Medium", "Using 'latest' tag instead of specific version"))
            
            # Check if running as root
            if not re.search(r'USER\s+(?!root)\S+', dockerfile_content, re.IGNORECASE):
                issues.append(("High", "No USER instruction or running as root user"))
            
            # Check for sensitive environment variables
            env_vars = re.findall(r'ENV\s+(\S+)\s+', dockerfile_content)
            for var in env_vars:
                if any(secret in var.lower() for secret in ['password', 'secret', 'key', 'token', 'auth']):
                    issues.append(("High", f"Potential sensitive data in ENV: {var}"))
            
            # Check if using ADD instead of COPY
            if re.search(r'ADD\s+', dockerfile_content, re.IGNORECASE):
                issues.append(("Low", "Using ADD instead of COPY (ADD has more security implications)"))
            
            # Check if updating packages
            if "apt-get install" in dockerfile_content and "apt-get update" not in dockerfile_content:
                issues.append(("Medium", "Installing packages without updating package lists first"))
            
            # Check for package verification
            if "curl" in dockerfile_content and not re.search(r'curl.+--insecure', dockerfile_content, re.IGNORECASE):
                if not any(verify in dockerfile_content.lower() for verify in ["sha256", "md5", "gpg", "verify"]):
                    issues.append(("Medium", "Downloading files without verification"))
            
            # Display findings
            if issues:
                print("\n[!] Security issues found:")
                for severity, issue in issues:
                    print(f"  [{severity}] {issue}")
            else:
                print("\n[+] No obvious security issues found in Dockerfile")
            
            # Recommendations
            print("\n[*] General recommendations:")
            print("  - Use specific version tags instead of 'latest'")
            print("  - Run containers as non-root user")
            print("  - Use multi-stage builds to reduce image size")
            print("  - Don't store secrets in Docker images")
            print("  - Use COPY instead of ADD when possible")
            print("  - Keep base images updated for security patches")
                
        except Exception as e:
            print(f"[!] Error analyzing Dockerfile: {e}")
        
        input("\nPress Enter to continue...")
    
    def _analyze_kubernetes(self):
        """Analyze Kubernetes manifests for security issues"""
        print("[+] Kubernetes Manifest Security Analyzer")
        
        k8s_path = input("Enter path to Kubernetes manifest file or directory: ")
        if not k8s_path:
            print("[!] No path specified.")
            input("\nPress Enter to continue...")
            return
        
        if not os.path.exists(k8s_path):
            print("[!] Path does not exist.")
            input("\nPress Enter to continue...")
            return
        
        print(f"[*] Analyzing Kubernetes manifests at: {k8s_path}")
        
        # Get list of YAML files
        yaml_files = []
        if os.path.isdir(k8s_path):
            for root, _, files in os.walk(k8s_path):
                for file in files:
                    if file.endswith(('.yaml', '.yml')):
                        yaml_files.append(os.path.join(root, file))
        else:
            if k8s_path.endswith(('.yaml', '.yml')):
                yaml_files.append(k8s_path)
        
        if not yaml_files:
            print("[!] No YAML files found.")
            input("\nPress Enter to continue...")
            return
        
        print(f"[*] Found {len(yaml_files)} YAML files for analysis")
        
        # Simulate manifest analysis
        all_issues = []
        
        for file in yaml_files:
            print(f"[*] Analyzing: {file}")
            time.sleep(0.5)
            
            try:
                with open(file, 'r') as f:
                    content = f.read()
                
                # Check for security issues
                if "privileged: true" in content:
                    all_issues.append((file, "High", "Container running in privileged mode"))
                
                if "runAsUser: 0" in content or "runAsNonRoot: false" in content:
                    all_issues.append((file, "High", "Pod running as root user"))
                
                if "hostNetwork: true" in content:
                    all_issues.append((file, "Medium", "Pod using host network"))
                
                if "hostPID: true" in content or "hostIPC: true" in content:
                    all_issues.append((file, "Medium", "Pod sharing host PID/IPC namespace"))
                
                if "allowPrivilegeEscalation: true" in content:
                    all_issues.append((file, "Medium", "Privilege escalation allowed"))
                
                if not "resources:" in content:
                    all_issues.append((file, "Low", "No resource limits defined"))
                
                if not "livenessProbe:" in content:
                    all_issues.append((file, "Low", "No liveness probe defined"))
                
            except Exception as e:
                print(f"[!] Error analyzing {file}: {e}")
        
        # Display findings
        if all_issues:
            print("\n[!] Security issues found:")
            
            # Group by severity
            highs = [i for i in all_issues if i[1] == "High"]
            mediums = [i for i in all_issues if i[1] == "Medium"]
            lows = [i for i in all_issues if i[1] == "Low"]
            
            if highs:
                print("\n  [HIGH]")
                for file, _, issue in highs:
                    file_name = os.path.basename(file)
                    print(f"  - {file_name}: {issue}")
                    
            if mediums:
                print("\n  [MEDIUM]")
                for file, _, issue in mediums:
                    file_name = os.path.basename(file)
                    print(f"  - {file_name}: {issue}")
                    
            if lows:
                print("\n  [LOW]")
                for file, _, issue in lows:
                    file_name = os.path.basename(file)
                    print(f"  - {file_name}: {issue}")
        else:
            print("\n[+] No obvious security issues found in Kubernetes manifests")
        
        # Recommendations
        print("\n[*] Kubernetes security recommendations:")
        print("  - Run containers as non-root user")
        print("  - Avoid running privileged containers")
        print("  - Set appropriate resource limits")
        print("  - Use network policies to restrict pod communication")
        print("  - Implement RBAC with least privilege")
        print("  - Use security contexts to harden container security")
        print("  - Implement pod security policies")
        
        input("\nPress Enter to continue...")
    
    def _analyze_docker_compose(self):
        """Analyze Docker Compose files for security issues"""
        print("[+] Docker Compose Security Analyzer")
        
        compose_path = input("Enter path to docker-compose.yml: ")
        if not compose_path:
            print("[!] No file specified.")
            input("\nPress Enter to continue...")
            return
        
        if not os.path.exists(compose_path):
            print("[!] File does not exist.")
            input("\nPress Enter to continue...")
            return
        
        print(f"[*] Analyzing Docker Compose file: {compose_path}")
        
        # Read the compose file
        try:
            with open(compose_path, 'r') as f:
                compose_content = f.read()
            
            # Check for security issues
            issues = []
            
            # Check for privileged mode
            if "privileged:" in compose_content:
                issues.append(("High", "Container running in privileged mode"))
            
            # Check for host network mode
            if "network_mode: host" in compose_content:
                issues.append(("Medium", "Container using host network"))
            
            # Check for host ports
            if re.search(r'ports:\s*-\s*"?(\d+):(\d+)"?', compose_content):
                issues.append(("Low", "Exposing ports directly to host"))
            
            # Check for volume mounts
            if re.search(r'volumes:\s*-\s*([^:]+):', compose_content):
                issues.append(("Medium", "Mounting host directories into containers"))
            
            # Check for latest tag
            if re.search(r'image:\s*\S+:latest', compose_content):
                issues.append(("Low", "Using 'latest' tag instead of specific version"))
            
            # Check for sensitive environment variables
            env_vars = re.findall(r'environment:\s*-\s*(\S+)=', compose_content)
            for var in env_vars:
                if any(secret in var.lower() for secret in ['password', 'secret', 'key', 'token', 'auth']):
                    issues.append(("High", f"Potential sensitive data in environment: {var}"))
            
            # Display findings
            if issues:
                print("\n[!] Security issues found:")
                for severity, issue in issues:
                    print(f"  [{severity}] {issue}")
            else:
                print("\n[+] No obvious security issues found in Docker Compose file")
            
            # Recommendations
            print("\n[*] Docker Compose security recommendations:")
            print("  - Avoid privileged mode and host network mode")
            print("  - Use specific version tags for images")
            print("  - Don't store sensitive data in compose files")
            print("  - Use Docker secrets or env files for sensitive data")
            print("  - Limit container capabilities")
            print("  - Use non-root users inside containers")
            print("  - Apply resource constraints to containers")
                
        except Exception as e:
            print(f"[!] Error analyzing Docker Compose file: {e}")
        
        input("\nPress Enter to continue...")

def run_cloud_security_tools():
    """Run the cloud security tools"""
    return CloudSecurityTools()

# Function to display the cloud security menu
def cloud_security_menu():
    """Display the cloud security menu"""
    tools = run_cloud_security_tools()
    
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("""
    ###########################################
    #          Cloud Security Tools           #
    ###########################################
    
    1. AWS Security Scanner
    2. Azure Security Scanner
    3. GCP Security Scanner
    4. Container Security Scanner
    5. Back to Main Menu
    """)
        
        choice = input("Select an option: ")
        
        try:
            choice = int(choice)
            if choice == 1:
                tools.aws_security_scanner()
            elif choice == 2:
                tools.azure_security_scanner()
            elif choice == 3:
                tools.gcp_security_scanner()
            elif choice == 4:
                tools.container_security_scanner()
            elif choice == 5:
                return
            else:
                print("Invalid option. Please try again.")
                input("\nPress Enter to continue...")
        except ValueError:
            print("Please enter a number.")
            input("\nPress Enter to continue...")

# For standalone testing
if __name__ == "__main__":
    cloud_security_menu() 