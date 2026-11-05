export type Finding = {
  id: string;
  code: string;
  title: string;
  points: number;
  evidence: string;
  reason: string;
  confidence: string;
  state: string;
};
export type IOC = {
  id: string;
  value: string;
  type: string;
  source: string;
  reason: string;
  reputation: string;
  confidence: string;
  first_observed: string;
  evidence: { source: string; excerpt: string }[];
  assessment: string;
  investigation_id?: string;
  investigation_name?: string;
  simulation?: boolean;
  lookups?: Intelligence[];
};
export type Technique = {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
};
export type Mapping = Technique & {
  state: string;
  confidence: string;
  evidence: string[];
  justification: string;
};
export type Risk = {
  score: number;
  severity: string;
  confidence: string;
  reasoning: string;
  compromise: string;
  factors: Finding[];
  limitations: string[];
};
export type CaseSummary = {
  id: string;
  name: string;
  created_at: string;
  simulation: boolean;
  status: string;
  subject: string;
  sender: string;
  risk: Risk;
  ioc_count: number;
  finding_count: number;
};
export type Intelligence = {
  provider: string;
  indicator: string;
  checked_at: string;
  status: string;
  reputation: string;
  message: string;
  source_url: string | null;
  detections: Record<string, unknown> | null;
  cached?: boolean;
};
export type Analysis = {
  engine_version: string;
  analyzed_at: string;
  parsed: {
    sender: string;
    recipient: string;
    reply_to: string;
    subject: string;
    date: string;
    message_id: string;
    received: string[];
    headers: { name: string; value: string }[];
    authentication: Record<
      string,
      { result: string; evidence: string[]; trust: string }
    >;
    plain_text: string;
    html_body: string;
    html_text: string;
    attachments: {
      filename: string;
      original_filename: string;
      content_type: string;
      size: number;
      sha256: string;
      md5: string;
      sha1: string;
    }[];
    mime: {
      index: number;
      type: string;
      disposition: string | null;
      filename: string | null;
    }[];
  };
  findings: Finding[];
  iocs: IOC[];
  mappings: Mapping[];
  risk: Risk;
  recommendations: {
    phase: string;
    action: string;
    reason: string;
    evidence: string[];
  }[];
  limitations: string[];
};
export type Investigation = CaseSummary & {
  raw_email: string;
  evidence_sha256: string;
  notes: string;
  revision_id: string;
  analysis: Analysis;
  revisions: { id: string; created_at: string; engine_version: string }[];
  intelligence: Intelligence[];
  exports: {
    id: string;
    format: string;
    created_at: string;
    revision_id: string;
    sha256: string;
  }[];
};
export type Sample = {
  id: string;
  name: string;
  description: string;
  raw_email: string;
  simulation: boolean;
};
export type Preferences = {
  analyst_name: string;
  classification: "CONFIDENTIAL" | "INTERNAL" | "PUBLIC";
  organization: string;
  default_input: "paste" | "upload" | "sample";
};
export type Settings = {
  preferences: Preferences;
  providers: {
    id: string;
    configured: boolean;
    environment_variable: string;
    last_status: string;
    last_checked: string | null;
  }[];
  version: string;
  max_upload_mb: number;
  database: string;
  investigations: number;
};
export type Dashboard = {
  total: number;
  completed: number;
  pending: number;
  confirmed_malicious: number;
  severities: Record<string, number>;
  ioc_categories: Record<string, number>;
  timeline: { date: string; investigations: number }[];
  recent: CaseSummary[];
};
