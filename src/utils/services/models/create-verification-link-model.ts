export interface CreateVerificationLinkModel {
  partner_id: string;
  signature: string;
  timestamp: string;
  name: string;
  company_name: string;
  id_types: IdType[];
  callback_url: string;
  data_privacy_policy_url: string;
  logo_url: string;
  is_single_use: boolean;
  user_id: string;
  expires_at: string;
}

export interface IdType {
  country: string;
  id_type: string;
  verification_method: string;
}

export interface CreateSmileLinkResponse {
  link: string;
  ref_id: string;
  success: boolean;
  error: string;
}
