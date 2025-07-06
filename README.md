# The THREAT Framework
---

## Framework Overview

The Tactics, Techniques, and Procedures for Human Risk Evaluation and Assessment Taxonomy (THREAT) is a comprehensive framework for understanding, analyzing, and defending against physical security threats. The THREAT framework provides a structured approach to categorizing adversary tactics, techniques, and procedures (TTPs) in physical environments, with a focus on human-centric risk evaluation.

### Core Principles:
- **Standardization**: Common language for physical threat analysis
- **Comprehensiveness**: Coverage of all physical threat vectors
- **Actionability**: Practical guidance for defense and response
- **Scalability**: Applicable across sectors and threat levels
- **Integration**: Bridges physical and cyber security domains
- **Human-Centric**: Focuses on human risk factors and behavioral assessment

---

## THREAT Tactical Matrix Structure

### Phase 1: PRE-ATTACK
**Objective**: Prepare for and enable physical attack operations

#### TA0001 - RECONNAISSANCE
*Gathering information about targets, facilities, and security measures*

**T1001 - Physical Surveillance**
- T1001.001: Static Observation (fixed position monitoring)
- T1001.002: Mobile Surveillance (following targets/vehicles)
- T1001.003: Aerial Reconnaissance (drones, aircraft)
- T1001.004: Technical Surveillance (cameras, listening devices)

**T1002 - Open Source Intelligence**
- T1002.001: Social Media Analysis
- T1002.002: Public Records Research
- T1002.003: News and Media Monitoring
- T1002.004: Facility Layout Research

**T1003 - Social Engineering**
- T1003.001: Pretext Calling
- T1003.002: Impersonation
- T1003.003: Elicitation
- T1003.004: Tailgating Reconnaissance

**T1004 - Physical Probing**
- T1004.001: Perimeter Testing
- T1004.002: Access Point Identification
- T1004.003: Security System Assessment
- T1004.004: Guard Pattern Analysis

#### TA0002 - RESOURCE DEVELOPMENT
*Acquiring tools, weapons, vehicles, and capabilities*

**T1005 - Acquire Infrastructure**
- T1005.001: Safe Houses
- T1005.002: Surveillance Posts
- T1005.003: Escape Routes
- T1005.004: Communication Systems

**T1006 - Develop Capabilities**
- T1006.001: Weapons Acquisition
- T1006.002: Technical Tools
- T1006.003: Disguises and Credentials
- T1006.004: Vehicle Procurement

**T1007 - Establish Accounts**
- T1007.001: False Identities
- T1007.002: Shell Companies
- T1007.003: Financial Accounts
- T1007.004: Communication Accounts

#### TA0003 - INITIAL ACCESS
*Gaining entry to facilities, events, or proximity to targets*

**T1008 - Valid Credentials**
- T1008.001: Stolen Badges/Keys
- T1008.002: Forged Documents
- T1008.003: Compromised Accounts
- T1008.004: Insider Assistance

**T1009 - Physical Bypass**
- T1009.001: Lock Picking
- T1009.002: Barrier Breach
- T1009.003: Alarm Circumvention
- T1009.004: Sensor Evasion

**T1010 - Social Engineering Access**
- T1010.001: Tailgating
- T1010.002: Impersonation
- T1010.003: Delivery Deception
- T1010.004: Emergency Exploitation

### Phase 2: ATTACK
**Objective**: Execute attack operations within target environment

#### TA0004 - PERSISTENCE
*Maintaining presence in facilities or operational areas*

**T1011 - Establish Foothold**
- T1011.001: Hidden Positions
- T1011.002: Legitimate Cover
- T1011.003: Insider Network
- T1011.004: Technical Persistence

**T1012 - Maintain Access**
- T1012.001: Credential Renewal
- T1012.002: Access Point Maintenance
- T1012.003: Counter-surveillance
- T1012.004: Adaptive Positioning

#### TA0005 - PRIVILEGE ESCALATION
*Gaining access to restricted areas or higher-value targets*

**T1013 - Exploit Relationships**
- T1013.001: Authority Impersonation
- T1013.002: Trust Exploitation
- T1013.003: Coercion
- T1013.004: Insider Recruitment

**T1014 - Physical Escalation**
- T1014.001: Restricted Area Access
- T1014.002: Executive Access
- T1014.003: Critical System Access
- T1014.004: Sensitive Information Access

#### TA0006 - DEFENSE EVASION
*Avoiding detection by security systems and personnel*

**T1015 - Avoid Detection**
- T1015.001: Surveillance Evasion
- T1015.002: Disguise and Concealment
- T1015.003: Timing Manipulation
- T1015.004: Route Obfuscation

**T1016 - Disable Security**
- T1016.001: Camera Interference
- T1016.002: Alarm Disabling
- T1016.003: Communication Jamming
- T1016.004: Sensor Blocking

#### TA0007 - CREDENTIAL ACCESS
*Obtaining badges, keys, passwords, or identity credentials*

**T1017 - Credential Theft**
- T1017.001: Badge Cloning
- T1017.002: Key Duplication
- T1017.003: Password Capture
- T1017.004: Biometric Spoofing

**T1018 - Credential Harvesting**
- T1018.001: Dumpster Diving
- T1018.002: Shoulder Surfing
- T1018.003: Device Theft
- T1018.004: Social Engineering

#### TA0008 - DISCOVERY
*Gathering information about layout, schedules, security measures*

**T1019 - Internal Reconnaissance**
- T1019.001: Facility Mapping
- T1019.002: Schedule Analysis
- T1019.003: Personnel Identification
- T1019.004: Security Assessment

**T1020 - System Discovery**
- T1020.001: Network Infrastructure
- T1020.002: Physical Security Systems
- T1020.003: Emergency Procedures
- T1020.004: Communication Systems

#### TA0009 - LATERAL MOVEMENT
*Moving through facilities or expanding operational area*

**T1021 - Internal Movement**
- T1021.001: Corridor Navigation
- T1021.002: Elevator Access
- T1021.003: Stairwell Movement
- T1021.004: Service Area Access

**T1022 - Area Expansion**
- T1022.001: Floor-to-Floor Movement
- T1022.002: Building-to-Building
- T1022.003: Campus Navigation
- T1022.004: Multi-Site Operations

#### TA0010 - COLLECTION
*Gathering intelligence, documents, or physical assets*

**T1023 - Document Theft**
- T1023.001: Physical Document Theft
- T1023.002: Photography/Scanning
- T1023.003: Digital Device Access
- T1023.004: Waste Collection

**T1024 - Asset Acquisition**
- T1024.001: Equipment Theft
- T1024.002: Material Sampling
- T1024.003: Prototype Access
- T1024.004: Intellectual Property

#### TA0011 - IMPACT
*Causing harm, damage, or disruption*

**T1025 - Physical Harm**
- T1025.001: Personnel Targeting
- T1025.002: Infrastructure Damage
- T1025.003: System Disruption
- T1025.004: Environmental Impact

**T1026 - Operational Impact**
- T1026.001: Service Disruption
- T1026.002: Process Interference
- T1026.003: Reputation Damage
- T1026.004: Financial Loss

### Phase 3: POST-ATTACK
**Objective**: Complete mission and manage attribution/exposure

#### TA0012 - EXFILTRATION
*Removing stolen assets or information*

**T1027 - Physical Exfiltration**
- T1027.001: Concealed Removal
- T1027.002: Legitimate Channel Abuse
- T1027.003: Dead Drop Operations
- T1027.004: Courier Networks

**T1028 - Digital Exfiltration**
- T1028.001: Network Transfer
- T1028.002: Removable Media
- T1028.003: Cloud Storage
- T1028.004: Communication Channels

#### TA0013 - COMMAND AND CONTROL
*Coordinating with external actors*

**T1029 - Communication**
- T1029.001: Direct Communication
- T1029.002: Encrypted Channels
- T1029.003: Dead Drops
- T1029.004: Signal Intelligence

**T1030 - Coordination**
- T1030.001: Team Coordination
- T1030.002: External Handler
- T1030.003: Network Operations
- T1030.004: Mission Updates

#### TA0014 - ATTRIBUTION MANAGEMENT
*Controlling whether and how attribution is established*

**T1031 - Attribution Avoidance**
- T1031.001: Identity Concealment
- T1031.002: False Flag Operations
- T1031.003: Misdirection
- T1031.004: Counter-Intelligence

**T1032 - Evidence Elimination**
- T1032.001: Physical Evidence Removal
- T1032.002: Digital Trace Cleanup
- T1032.003: Witness Management
- T1032.004: Surveillance Countermeasures

**T1033 - Controlled Attribution**
- T1033.001: Selective Evidence Placement
- T1033.002: Symbolic Messaging
- T1033.003: Staged Discovery
- T1033.004: Timed Revelation

#### TA0015 - PUBLIC MESSAGING
*Claiming responsibility and communicating motivations*

**T1034 - Responsibility Claims**
- T1034.001: Media Statements
- T1034.002: Social Media Announcements
- T1034.003: Direct Communication to Authorities
- T1034.004: Manifesto Publication

**T1035 - Message Amplification**
- T1035.001: Multiple Platform Broadcasting
- T1035.002: Sympathizer Networks
- T1035.003: Media Manipulation
- T1035.004: Viral Content Creation

**T1036 - Symbolic Communication**
- T1036.001: Attack Site Messaging
- T1036.002: Victim Selection Messaging
- T1036.003: Method/Timing Symbolism
- T1036.004: Cultural/Religious References

#### TA0016 - SURRENDER/CAPTURE
*Facilitating apprehension while controlling narrative*

**T1037 - Planned Surrender**
- T1037.001: Controlled Surrender Location
- T1037.002: Media-Present Surrender
- T1037.003: Symbolic Surrender Timing
- T1037.004: Lawyer-Mediated Surrender

**T1038 - Capture Facilitation**
- T1038.001: Obvious Evidence Trails
- T1038.002: Location Disclosure
- T1038.003: Witness Cultivation
- T1038.004: Surveillance Exposure

**T1039 - Martyrdom Preparation**
- T1039.001: Final Messages
- T1039.002: Legacy Documentation
- T1039.003: Posthumous Instructions
- T1039.004: Symbolic Final Actions

---

## THREAT Actor Profiles

### Insider Threats (G0001)
**Description**: Individuals with authorized access who pose threats from within
**Motivations**: Financial gain, grievance, ideology, coercion
**Capabilities**: High access, low suspicion, knowledge of procedures
**Common TTPs**: T1008, T1013, T1019, T1023

### Organized Crime (G0002)
**Description**: Criminal organizations focused on profit-driven activities
**Motivations**: Financial gain, territory control, resource acquisition
**Capabilities**: Professional tools, network resources, corruption
**Common TTPs**: T1001, T1006, T1017, T1025

### Terrorists (G0003)
**Description**: Ideologically motivated groups seeking to cause fear and disruption
**Motivations**: Political change, religious ideology, social disruption
**Capabilities**: Weapons, explosives, martyrdom operations
**Common TTPs**: T1002, T1025, T1026, T1034, T1036

### Nation-State Actors (G0004)
**Description**: State-sponsored groups conducting espionage or sabotage
**Motivations**: National security, economic advantage, political influence
**Capabilities**: Advanced resources, intelligence support, diplomatic cover
**Common TTPs**: T1001, T1005, T1020, T1028, T1031

### Activists (G0005)
**Description**: Groups pursuing political or social change through direct action
**Motivations**: Environmental protection, social justice, political reform
**Capabilities**: Media savvy, public support, coordinated actions
**Common TTPs**: T1002, T1010, T1026, T1034, T1035

### Lone Actors (G0006)
**Description**: Individuals acting independently with personal motivations
**Motivations**: Grievance, mental health, ideology, attention-seeking
**Capabilities**: Limited resources, unpredictable, insider knowledge
**Common TTPs**: T1003, T1009, T1025, T1037, T1039

---

## THREAT Detection and Monitoring

### Data Sources

#### Physical Security Systems
- **Access Control Logs**: Badge readers, turnstiles, door sensors
- **Video Surveillance**: CCTV cameras, motion detection, facial recognition
- **Intrusion Detection**: Motion sensors, glass break detectors, pressure mats
- **Perimeter Security**: Fence sensors, lighting systems, guard towers

#### Human Intelligence
- **Security Personnel**: Guard reports, patrol logs, incident reports
- **Employee Reports**: Suspicious activity, security concerns, observations
- **Visitor Management**: Guest logs, escort records, temporary access
- **Third-Party Reports**: Contractors, vendors, service providers

#### Digital-Physical Correlation
- **Network Access**: Location-based login attempts, device connections
- **Communication Intercepts**: Phone calls, radio transmissions, digital messages
- **Financial Transactions**: Credit card usage, ATM withdrawals, expense reports
- **Transportation**: Vehicle tracking, public transit, parking records

### Detection Indicators

#### Behavioral Indicators
- **Unusual Presence**: Loitering, repeated visits, presence at odd hours
- **Suspicious Activities**: Photography, questioning, probing behavior
- **Relationship Anomalies**: Unexpected contacts, new associations
- **Behavioral Changes**: Stress indicators, lifestyle changes, attitude shifts

#### Technical Indicators
- **System Anomalies**: Failed access attempts, unusual patterns, sensor triggers
- **Communication Patterns**: Encrypted communications, suspicious contacts
- **Digital Footprints**: Location data, search histories, purchase patterns
- **Environmental Changes**: Missing items, moved objects, tampered systems

### Mitigation Strategies

#### Preventive Controls
- **Access Management**: Multi-factor authentication, role-based access, regular reviews
- **Physical Barriers**: Fencing, barriers, secure doors, reinforced structures
- **Surveillance Systems**: Cameras, motion sensors, lighting, guard presence
- **Personnel Security**: Background checks, training, awareness programs

#### Detective Controls
- **Monitoring Systems**: Real-time alerts, pattern analysis, anomaly detection
- **Audit Procedures**: Regular inspections, log reviews, compliance checks
- **Intelligence Gathering**: Threat monitoring, information sharing, analysis
- **Incident Response**: Rapid response teams, escalation procedures, communication

#### Corrective Controls
- **Incident Response**: Containment, investigation, recovery, lessons learned
- **Law Enforcement**: Coordination, evidence collection, prosecution support
- **Emergency Procedures**: Evacuation, lockdown, medical response, continuity
- **Remediation**: System updates, process improvements, training enhancement

---

## THREAT Framework Implementation Guidelines

### Phase 1: Foundation (Months 1-6)
- Establish core THREAT framework structure
- Define key tactics and techniques for human risk evaluation
- Develop initial threat actor profiles
- Create basic detection guidance

### Phase 2: Expansion (Months 7-12)
- Add sector-specific techniques to the THREAT framework
- Develop comprehensive mitigation strategies
- Create threat hunting methodologies using THREAT taxonomy
- Build training materials for THREAT framework implementation

### Phase 3: Integration (Months 13-18)
- Integrate THREAT framework with existing security tools
- Develop APIs and data feeds for the THREAT taxonomy
- Create incident response playbooks based on THREAT TTPs
- Establish community feedback mechanisms for THREAT framework

### Phase 4: Optimization (Months 19-24)
- Refine THREAT framework based on operational feedback
- Add advanced analytics capabilities to THREAT taxonomy
- Expand international coverage of THREAT framework
- Develop certification programs for THREAT framework practitioners

### Success Metrics
- **Adoption Rate**: Organizations using the THREAT framework
- **Coverage**: Percentage of known threats categorized in THREAT taxonomy
- **Effectiveness**: Successful threat detections and responses using THREAT framework
- **Community**: Active contributors and feedback providers for THREAT framework
- **Integration**: Tools and platforms supporting the THREAT framework

---

## Conclusion

The Tactics, Techniques, and Procedures for Human Risk Evaluation and Assessment Taxonomy (THREAT) framework provides a comprehensive, structured approach to understanding and defending against physical security threats. By adapting the successful MITRE ATT&CK model to the physical domain with a focus on human risk evaluation, the THREAT framework enables security professionals to standardize their approach to threat analysis, improve detection capabilities, and enhance overall security posture.

The THREAT framework's strength lies in its systematic categorization of adversary behavior, practical guidance for defense, and integration with existing security programs. As threats continue to evolve, the THREAT framework provides the foundation for adaptive, intelligence-driven physical security operations with enhanced human risk assessment capabilities.
