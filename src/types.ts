export interface User {
  id: string;
  email: string;
  name: string;
  last_check_in: string;
  status: 'active' | 'pending' | 'released';
  check_in_frequency_days: number;
}

export interface Category {
  id: string;
  user_id: string;
  name: string;
  icon: string;
  is_custom: boolean;
}

export interface Document {
  id: string;
  section_id: string;
  user_id: string;
  title: string;
  file_name: string;
  file_type: string;
  priority: 'High' | 'Medium' | 'Low';
  notes?: string;
  beneficiary_id?: string;
  integrity_hash?: string;
  created_at: string;
}

export interface TrustedContact {
  id: string;
  user_id: string;
  name: string;
  email: string;
  relationship: string;
  status: 'pending' | 'verified';
}

export interface MemoryCapsule {
  id: string;
  user_id: string;
  recipient_name: string;
  recipient_email: string;
  message: string;
  unlock_condition: string;
}
