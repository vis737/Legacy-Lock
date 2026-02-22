import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { 
  Shield, 
  Lock, 
  Users, 
  FileText, 
  Plus, 
  Clock, 
  AlertTriangle, 
  Database,
  Eye,
  Activity,
  CheckCircle2,
  Download,
  Zap,
  Bell,
  FolderPlus,
  Menu,
  X,
  File,
  Trash2,
  Upload,
  LogOut,
  User as UserIcon,
  ArrowRight,
  Globe,
  MessageSquare,
  History,
  CheckSquare,
  Cpu,
  BarChart3,
  Heart,
  Calendar,
  Award,
  RefreshCw
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  generateDigitalWill, 
  analyzeLifePatterns, 
  scanVaultIntelligence, 
  draftLegacyMessage 
} from './services/geminiService';

// --- Types ---
interface User {
  id: string;
  email: string;
  name: string;
  country?: string;
  last_check_in?: string;
}

interface Section {
  id: string;
  name: string;
  icon: string;
}

interface Document {
  id: string;
  section_id: string;
  title: string;
  file_type: string;
  priority: 'High' | 'Medium' | 'Low';
  notes: string;
  beneficiary_id?: string;
  version_count?: number;
  integrity_hash?: string;
}

interface Contact {
  id: string;
  name: string;
  email: string;
  relationship: string;
  access_code?: string;
  status: 'active' | 'verified';
}

interface LegacyMessage {
  id: string;
  recipient_id: string;
  category: string;
  type: string;
  content: string;
  release_event: string;
  status: string;
}

interface ConfidentialLink {
  id: string;
  beneficiary_id: string;
  title: string;
  username: string;
  password: string;
  notes: string;
}

interface Notification {
  id: string;
  title: string;
  message: string;
  type: 'info' | 'warning' | 'alert';
  is_read: number;
  created_at: string;
}

// --- Components ---

const SidebarItem = ({ icon: Icon, label, active, onClick, disabled }: { icon: any, label: string, active: boolean, onClick: () => void, disabled?: boolean }) => (
  <button 
    onClick={disabled ? undefined : onClick}
    className={`w-full flex items-center space-x-3 px-4 py-3 rounded-xl transition-all duration-200 ${
      active ? 'bg-legacy-silver/10 text-legacy-silver border border-legacy-silver/20' : 
      disabled ? 'text-slate-600 cursor-not-allowed opacity-50' : 'text-slate-400 hover:bg-white/5 hover:text-white'
    }`}
  >
    <Icon size={20} />
    <span className="font-medium">{label}</span>
    {disabled && <span className="text-[10px] uppercase tracking-tighter bg-white/5 px-1.5 py-0.5 rounded text-slate-500">Soon</span>}
  </button>
);

const Card = ({ children, className = "", ...props }: { children: React.ReactNode, className?: string, [key: string]: any }) => (
  <div className={`glass rounded-2xl p-6 ${className}`} {...props}>
    {children}
  </div>
);

const Badge = ({ children, variant = 'default' }: { children: React.ReactNode, variant?: 'default' | 'success' | 'warning' | 'danger' }) => {
  const styles = {
    default: 'bg-white/10 text-slate-300',
    success: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20',
    warning: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
    danger: 'bg-rose-500/10 text-rose-400 border border-rose-500/20',
  };
  return (
    <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[variant]}`}>
      {children}
    </span>
  );
};

const PriorityColors = {
  High: 'danger',
  Medium: 'warning',
  Low: 'success'
} as const;

// --- Main App ---

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'));
  const [user, setUser] = useState<User | null>(() => {
    try {
      const saved = localStorage.getItem('user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [activeTab, setActiveTab] = useState('dashboard');
  const [showSimulation, setShowSimulation] = useState(false);
  const [simulationBeneficiary, setSimulationBeneficiary] = useState<string | null>(null);
  const [showJuryBrief, setShowJuryBrief] = useState(false);
  const [sections, setSections] = useState<Section[]>([]);
  const [documents, setDocuments] = useState<Document[]>([]);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<LegacyMessage[]>([]);
  const [confidentialLinks, setConfidentialLinks] = useState<ConfidentialLink[]>([]);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [escalationStage, setEscalationStage] = useState('Normal');
  const [loading, setLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [selectedSectionId, setSelectedSectionId] = useState<string | null>(null);
  
  // Beneficiary Portal State
  const [isBeneficiaryMode, setIsBeneficiaryMode] = useState(false);
  const [beneficiaryToken, setBeneficiaryToken] = useState<string | null>(() => localStorage.getItem('beneficiaryToken'));
  const [beneficiaryAssets, setBeneficiaryAssets] = useState<{ 
    documents: Document[], 
    messages: LegacyMessage[], 
    credentials: ConfidentialLink[], 
    owner?: { name: string, email: string, country: string, escalation_stage: string },
    verifications?: any[]
  } | null>(null);
  const [beneficiaryEmail, setBeneficiaryEmail] = useState('');
  const [beneficiaryPassword, setBeneficiaryPassword] = useState('');
  const [beneficiaryError, setBeneficiaryError] = useState('');

  // Death Verification State
  const [showDeathCertModal, setShowDeathCertModal] = useState(false);
  const [deathCertFile, setDeathCertFile] = useState<File | null>(null);
  const [deathVerifications, setDeathVerifications] = useState<any[]>([]);
  const [isUploadingDeathCert, setIsUploadingDeathCert] = useState(false);
  
  // Admin Portal State
  const [isAdminMode, setIsAdminMode] = useState(false);
  const [adminToken, setAdminToken] = useState<string | null>(() => localStorage.getItem('adminToken'));
  const [adminUsers, setAdminUsers] = useState<any[]>([]);
  const [adminVerifications, setAdminVerifications] = useState<any[]>([]);
  const [adminLogs, setAdminLogs] = useState<any[]>([]);
  const [adminError, setAdminError] = useState('');

  // Auth State
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [country, setCountry] = useState('United States');
  const [authError, setAuthError] = useState('');

  // Continuity Settings
  const [escalationConfig, setEscalationConfig] = useState({
    reminderDays: 7,
    wellnessDays: 14,
    circleDays: 21,
    activationDays: 30
  });

  // Vault Intelligence
  const [vaultInsights, setVaultInsights] = useState<any>(null);
  const [isScanningVault, setIsScanningVault] = useState(false);

  // Legacy Messages
  const [showAddMessage, setShowAddMessage] = useState(false);
  const [showConfidentialModal, setShowConfidentialModal] = useState(false);
  const [confTitle, setConfTitle] = useState('');
  const [confBeneficiary, setConfBeneficiary] = useState('');
  const [confNotes, setConfNotes] = useState('');
  const [msgRecipient, setMsgRecipient] = useState('');
  const [msgCategory, setMsgCategory] = useState('Celebration');
  const [msgType, setMsgType] = useState('Text');
  const [msgContent, setMsgContent] = useState('');
  const [msgEvent, setMsgEvent] = useState('');
  const [editingMessage, setEditingMessage] = useState<LegacyMessage | null>(null);
  const [isDraftingMsg, setIsDraftingMsg] = useState(false);

  // Modal States
  const [showAddSection, setShowAddSection] = useState(false);
  const [newSectionName, setNewSectionName] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadPriority, setUploadPriority] = useState<'High' | 'Medium' | 'Low'>('Medium');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadNotes, setUploadNotes] = useState('');
  const [uploadBeneficiary, setUploadBeneficiary] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isVerified, setIsVerified] = useState(false);
  const [isAuthBiometricStep, setIsAuthBiometricStep] = useState(false);
  const [cameraStream, setCameraStream] = useState<MediaStream | null>(null);
  const videoRef = React.useRef<HTMLVideoElement>(null);
  const authVideoRef = React.useRef<HTMLVideoElement>(null);

  // Auto-attach camera stream to video elements
  useEffect(() => {
    if (cameraStream) {
      if (isAuthBiometricStep && authVideoRef.current) {
        authVideoRef.current.srcObject = cameraStream;
      } else if (showUpload && videoRef.current) {
        videoRef.current.srcObject = cameraStream;
      }
    }
  }, [cameraStream, isAuthBiometricStep, showUpload]);

  // Auto-start camera when entering biometric steps
  useEffect(() => {
    if (isAuthBiometricStep || (showUpload && !isVerified)) {
      startCamera();
    } else {
      stopCamera();
    }
    return () => stopCamera();
  }, [isAuthBiometricStep, showUpload, isVerified]);

  // Trust Network State
  const [showAddContact, setShowAddContact] = useState(false);
  const [contactName, setContactName] = useState('');
  const [contactEmail, setContactEmail] = useState('');
  const [contactRelationship, setContactRelationship] = useState('');

  // Smart Will State
  const [generatedWill, setGeneratedWill] = useState<string | null>(null);
  const [isGeneratingWill, setIsGeneratingWill] = useState(false);

  // Risk Analysis State
  const [riskAssessment, setRiskAssessment] = useState<{ riskScore: number, reasoning: string, shouldTriggerEscalation: boolean } | null>(null);
  const [isAnalyzingRisk, setIsAnalyzingRisk] = useState(false);

  // Preview State
  const [previewDoc, setPreviewDoc] = useState<Document | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [isPreviewLoading, setIsPreviewLoading] = useState(false);

  const startCamera = async () => {
    if (cameraStream) return; 
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ 
        video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 640 } } 
      });
      setCameraStream(stream);
    } catch (err) {
      console.error("Error accessing camera:", err);
    }
  };

  const stopCamera = () => {
    if (cameraStream) {
      cameraStream.getTracks().forEach(track => track.stop());
      setCameraStream(null);
    }
  };

  const handleVerify = () => {
    setIsVerifying(true);
    // Simulate AI Face Verification
    setTimeout(() => {
      setIsVerifying(false);
      setIsVerified(true);
      stopCamera();
    }, 2000);
  };

  const fetchAll = useCallback(async () => {
    if (beneficiaryToken) {
      fetchBeneficiaryAssets();
      return;
    }
    if (!token) return;
    setLoading(true);
    try {
      const [secRes, docRes, conRes, msgRes, setRes, confRes, notiRes, deathRes] = await Promise.all([
        fetch('/api/sections', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/documents', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/contacts', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/messages', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/user/settings', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/confidential-links', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/notifications', { headers: { Authorization: `Bearer ${token}` } }),
        fetch('/api/death-verification', { headers: { Authorization: `Bearer ${token}` } })
      ]);
      if (secRes.ok) setSections(await secRes.json());
      if (docRes.ok) setDocuments(await docRes.json());
      if (conRes.ok) setContacts(await conRes.json());
      if (msgRes.ok) setMessages(await msgRes.json());
      if (confRes.ok) setConfidentialLinks(await confRes.json());
      if (notiRes.ok) setNotifications(await notiRes.json());
      if (deathRes.ok) setDeathVerifications(await deathRes.json());
      if (setRes.ok) {
        const settings = await setRes.json();
        if (settings.country) setCountry(settings.country);
        if (settings.escalation_config) setEscalationConfig(JSON.parse(settings.escalation_config));
        if (settings.escalation_stage) setEscalationStage(settings.escalation_stage);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [token, beneficiaryToken]);

  const fetchBeneficiaryAssets = async () => {
    if (!beneficiaryToken) return;
    const res = await fetch('/api/beneficiary/assets', {
      headers: { Authorization: `Bearer ${beneficiaryToken}` }
    });
    if (res.ok) {
      setBeneficiaryAssets(await res.json());
    } else {
      handleBeneficiaryLogout();
    }
  };

  useEffect(() => {
    if (token || beneficiaryToken) fetchAll();
  }, [token, beneficiaryToken, fetchAll]);

  const handleBeneficiaryConfirmWellness = async () => {
    if (!beneficiaryToken) return;
    try {
      const res = await fetch('/api/beneficiary/confirm-wellness', {
        method: 'POST',
        headers: { Authorization: `Bearer ${beneficiaryToken}` }
      });
      if (res.ok) {
        alert("Wellness confirmed. The owner's status has been reset to Normal.");
        fetchBeneficiaryAssets();
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError('');
    
    if (!isAuthBiometricStep) {
      setIsAuthBiometricStep(true);
      return;
    }

    setIsVerifying(true);
    
    setTimeout(async () => {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const body = isLogin ? { email, password } : { email, password, name, country };
      
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
        
        const contentType = res.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
          const data = await res.json();
          if (res.ok) {
            setToken(data.token);
            setUser(data.user);
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            stopCamera();
            setIsAuthBiometricStep(false);
          } else {
            setAuthError(data.error || 'Authentication failed');
            setIsAuthBiometricStep(false);
            stopCamera();
          }
        } else {
          setAuthError('Server error: Unexpected response format');
          setIsAuthBiometricStep(false);
          stopCamera();
        }
      } catch (e) {
        setAuthError('Authentication failed');
        setIsAuthBiometricStep(false);
        stopCamera();
      } finally {
        setIsVerifying(false);
      }
    }, 2000);
  };

  const handleBeneficiaryLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setBeneficiaryError('');
    try {
      const res = await fetch('/api/beneficiary/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: beneficiaryEmail, password: beneficiaryPassword })
      });
      const data = await res.json();
      if (res.ok) {
        setBeneficiaryToken(data.token);
        localStorage.setItem('beneficiaryToken', data.token);
      } else {
        setBeneficiaryError(data.error || 'Login failed');
      }
    } catch (e) {
      setBeneficiaryError('Connection error');
    }
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  };

  const handleBeneficiaryLogout = () => {
    setBeneficiaryToken(null);
    setBeneficiaryAssets(null);
    localStorage.removeItem('beneficiaryToken');
  };

  const handleAdminLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdminError('');
    try {
      const res = await fetch('/api/admin/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (res.ok) {
        setAdminToken(data.token);
        localStorage.setItem('adminToken', data.token);
      } else {
        setAdminError(data.error || 'Admin login failed');
      }
    } catch (e) {
      setAdminError('Connection error');
    }
  };

  const handleAdminLogout = () => {
    setAdminToken(null);
    localStorage.removeItem('adminToken');
  };

  const fetchAdminData = useCallback(async () => {
    if (!adminToken) return;
    try {
      const [usersRes, verRes, logsRes] = await Promise.all([
        fetch('/api/admin/users', { headers: { Authorization: `Bearer ${adminToken}` } }),
        fetch('/api/admin/verifications', { headers: { Authorization: `Bearer ${adminToken}` } }),
        fetch('/api/admin/logs', { headers: { Authorization: `Bearer ${adminToken}` } })
      ]);
      if (usersRes.ok) setAdminUsers(await usersRes.json());
      if (verRes.ok) setAdminVerifications(await verRes.json());
      if (logsRes.ok) setAdminLogs(await logsRes.json());
    } catch (e) {
      console.error("Failed to fetch admin data", e);
    }
  }, [adminToken]);

  useEffect(() => {
    if (adminToken) {
      fetchAdminData();
      const interval = setInterval(fetchAdminData, 5000);
      return () => clearInterval(interval);
    }
  }, [adminToken, fetchAdminData]);

  const handleDeathCertUpload = async () => {
    if (!deathCertFile) return;
    setIsUploadingDeathCert(true);
    const formData = new FormData();
    formData.append('file', deathCertFile);
    
    const currentToken = beneficiaryToken || token;
    const endpoint = beneficiaryToken ? '/api/beneficiary/death-verification' : '/api/death-verification';
    
    if (!beneficiaryToken && simulationBeneficiary) {
      formData.append('beneficiary_id', simulationBeneficiary);
    }

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { Authorization: `Bearer ${currentToken}` },
        body: formData
      });
      if (res.ok) {
        setShowDeathCertModal(false);
        setDeathCertFile(null);
        fetchAll();
        alert("Death certificate uploaded for verification.");
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsUploadingDeathCert(false);
    }
  };

  const verifyDeath = async (id: string) => {
    const res = await fetch(`/api/death-verification/${id}/verify`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) {
      fetchAll();
      alert("Death verified. Legacy Activation triggered.");
    }
  };

  const downloadBeneficiaryAsset = async (doc: Document) => {
    try {
      const res = await fetch(`/api/beneficiary/download/${doc.id}`, {
        headers: { Authorization: `Bearer ${beneficiaryToken}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = doc.title;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleCheckIn = async () => {
    if (!token) return;
    try {
      const res = await fetch('/api/check-in', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setUser(prev => prev ? { ...prev, last_check_in: data.last_check_in } : null);
        setEscalationStage('Normal');
        // Clear notifications related to check-in
        await fetch('/api/notifications/read', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}` }
        });
        fetchAll();
        alert("Continuity confirmed. System status: Normal.");
      }
    } catch (e) {
      console.error(e);
    }
  };

  const simulateEscalation = async (stage: string) => {
    const res = await fetch('/api/simulate/escalation', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ stage })
    });
    if (res.ok) {
      setEscalationStage(stage);
      fetchAll();
    }
  };

  const downloadDocument = async (doc: Document) => {
    try {
      const res = await fetch(`/api/documents/${doc.id}/download`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = doc.title;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      } else {
        alert("Failed to download document.");
      }
    } catch (e) {
      console.error(e);
      alert("Error downloading document.");
    }
  };

  const addContact = async () => {
    if (!contactName || !contactEmail) return;
    const res = await fetch('/api/contacts', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ name: contactName, email: contactEmail, relationship: contactRelationship })
    });
    if (res.ok) {
      const newCon = await res.json();
      setContacts([newCon, ...contacts]);
      setContactName('');
      setContactEmail('');
      setContactRelationship('');
      setShowAddContact(false);
    }
  };

  const deleteContact = async (id: string) => {
    const res = await fetch(`/api/contacts/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) {
      setContacts(contacts.filter(c => c.id !== id));
    }
  };

  const handleGenerateWill = async () => {
    setIsGeneratingWill(true);
    try {
      const userData = {
        user: user,
        documents: documents,
        contacts: contacts
      };
      const will = await generateDigitalWill(userData, country);
      setGeneratedWill(will || "Failed to generate plan.");
    } catch (e) {
      console.error(e);
      setGeneratedWill("Error generating continuity plan.");
    } finally {
      setIsGeneratingWill(false);
    }
  };

  const handleScanVault = async () => {
    setIsScanningVault(true);
    try {
      const insights = await scanVaultIntelligence(documents);
      setVaultInsights(insights);
    } catch (e) {
      console.error(e);
    } finally {
      setIsScanningVault(false);
    }
  };

  const handleDraftMessage = async () => {
    if (!msgContent) return;
    setIsDraftingMsg(true);
    try {
      const drafted = await draftLegacyMessage(msgContent, "Warm");
      setMsgContent(drafted || msgContent);
    } catch (e) {
      console.error(e);
    } finally {
      setIsDraftingMsg(false);
    }
  };

  const saveMessage = async () => {
    if (!msgRecipient || !msgContent) return;
    
    if (editingMessage) {
      const res = await fetch(`/api/messages/${editingMessage.id}`, {
        method: 'PATCH',
        headers: { 
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({
          recipient_id: msgRecipient,
          category: msgCategory,
          content: msgContent,
          release_event: msgEvent
        })
      });
      if (res.ok) {
        setMessages(messages.map(m => m.id === editingMessage.id ? { ...m, recipient_id: msgRecipient, category: msgCategory, content: msgContent, release_event: msgEvent } : m));
        setShowAddMessage(false);
        setEditingMessage(null);
        setMsgContent('');
      }
      return;
    }

    const res = await fetch('/api/messages', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        recipient_id: msgRecipient,
        category: msgCategory,
        type: msgType,
        content: msgContent,
        release_event: msgEvent
      })
    });
    if (res.ok) {
      const newMsg = await res.json();
      setMessages([newMsg, ...messages]);
      setShowAddMessage(false);
      setMsgContent('');
    }
  };

  const deleteMessage = async (id: string) => {
    const res = await fetch(`/api/messages/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) {
      setMessages(messages.filter(m => m.id !== id));
    }
  };

  const generateConfidentialLink = async () => {
    if (!confTitle || !confBeneficiary) return;
    
    const randomUser = 'user_' + Math.random().toString(36).substring(2, 8);
    const randomPass = Math.random().toString(36).substring(2, 12) + '!';
    
    const res = await fetch('/api/confidential-links', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        beneficiary_id: confBeneficiary,
        title: confTitle,
        username: randomUser,
        password: randomPass,
        notes: confNotes
      })
    });
    
    if (res.ok) {
      const newLink = await res.json();
      setConfidentialLinks([newLink, ...confidentialLinks]);
      setShowConfidentialModal(false);
      setConfTitle('');
      setConfNotes('');
    }
  };

  const deleteConfidentialLink = async (id: string) => {
    const res = await fetch(`/api/confidential-links/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) {
      setConfidentialLinks(confidentialLinks.filter(l => l.id !== id));
    }
  };

  const handleBlockchainVerify = async (docId: string) => {
    try {
      const res = await fetch('/api/blockchain/verify', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ document_id: docId })
      });
      if (res.ok) {
        const proof = await res.json();
        setDocuments(documents.map(d => d.id === docId ? { ...d, integrity_hash: proof.hash } : d));
        alert("Blockchain Integrity Proof generated successfully!");
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleAnalyzeRisk = async () => {
    setIsAnalyzingRisk(true);
    try {
      const activityLogs = [
        { type: 'check_in', date: user?.last_check_in || new Date().toISOString() },
        { type: 'vault_access', date: new Date().toISOString() }
      ];
      const analysis = await analyzeLifePatterns(activityLogs);
      setRiskAssessment(analysis);
    } catch (e) {
      console.error(e);
    } finally {
      setIsAnalyzingRisk(false);
    }
  };

  const addSection = async () => {
    if (!newSectionName) return;
    const res = await fetch('/api/sections', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ name: newSectionName })
    });
    if (res.ok) {
      const newSec = await res.json();
      setSections([newSec, ...sections]);
      setNewSectionName('');
      setShowAddSection(false);
    }
  };

  const deleteSection = async (id: string) => {
    const res = await fetch(`/api/sections/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) {
      setSections(sections.filter(s => s.id !== id));
      setDocuments(documents.filter(d => d.section_id !== id));
      if (selectedSectionId === id) setSelectedSectionId(null);
    }
  };

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadFile || !selectedSectionId) return;

    setIsUploading(true);
    setUploadProgress(0);

    const formData = new FormData();
    formData.append('file', uploadFile);
    formData.append('title', uploadTitle || uploadFile.name);
    formData.append('section_id', selectedSectionId);
    formData.append('priority', uploadPriority);
    formData.append('notes', uploadNotes);
    if (uploadBeneficiary) formData.append('beneficiary_id', uploadBeneficiary);

    try {
      const response = await axios.post('/api/documents', formData, {
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / (progressEvent.total || 1));
          setUploadProgress(percentCompleted);
        }
      });

      if (response.status === 200) {
        const newDoc = response.data;
        setDocuments([newDoc, ...documents]);
        setShowUpload(false);
        setUploadFile(null);
        setUploadTitle('');
        setUploadNotes('');
        setIsVerified(false);
      }
    } catch (error) {
      console.error("Upload error:", error);
      alert("Failed to upload document. Please try again.");
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  const deleteDocument = async (id: string) => {
    const res = await fetch(`/api/documents/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });
    if (res.ok) {
      setDocuments(documents.filter(d => d.id !== id));
    }
  };

  const updatePriority = async (id: string, priority: 'High' | 'Medium' | 'Low') => {
    const res = await fetch(`/api/documents/${id}`, {
      method: 'PATCH',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ priority })
    });
    if (res.ok) {
      setDocuments(documents.map(d => d.id === id ? { ...d, priority } : d));
    }
  };

  const updateNotes = async (id: string, notes: string) => {
    const res = await fetch(`/api/documents/${id}`, {
      method: 'PATCH',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ notes })
    });
    if (res.ok) {
      setDocuments(documents.map(d => d.id === id ? { ...d, notes } : d));
      if (previewDoc?.id === id) {
        setPreviewDoc({ ...previewDoc, notes });
      }
    }
  };

  const updateBeneficiary = async (id: string, beneficiary_id: string) => {
    const res = await fetch(`/api/documents/${id}`, {
      method: 'PATCH',
      headers: { 
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ beneficiary_id })
    });
    if (res.ok) {
      setDocuments(documents.map(d => d.id === id ? { ...d, beneficiary_id } : d));
      if (previewDoc?.id === id) {
        setPreviewDoc({ ...previewDoc, beneficiary_id });
      }
    }
  };

  const handlePreview = async (doc: Document) => {
    setIsPreviewLoading(true);
    setPreviewDoc(doc);
    try {
      const response = await axios.get(`/api/documents/${doc.id}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      
      const url = URL.createObjectURL(response.data);
      setPreviewUrl(url);
    } catch (error: any) {
      console.error("Preview error:", error);
      const errorMessage = error.response?.data?.error || error.message || "Failed to load document preview.";
      alert(errorMessage);
      setPreviewDoc(null);
    } finally {
      setIsPreviewLoading(false);
    }
  };

  const closePreview = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setPreviewUrl(null);
    setPreviewDoc(null);
  };

  if (adminToken) {
    return (
      <div className="min-h-screen bg-black text-emerald-500 font-mono selection:bg-emerald-500/30">
        <header className="border-b border-emerald-500/20 px-6 py-4 flex justify-between items-center bg-black/50 backdrop-blur-md sticky top-0 z-50">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 bg-emerald-500 rounded-lg flex items-center justify-center shadow-[0_0_15px_rgba(16,185,129,0.4)]">
              <Cpu className="text-black" size={24} />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-tighter uppercase italic">Legacy-Lock</h1>
              <p className="text-[10px] uppercase tracking-widest opacity-60">System Administrator Console</p>
            </div>
          </div>
          <button onClick={handleAdminLogout} className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 hover:bg-emerald-500/20 transition-colors">
            <LogOut size={18} />
            <span>Terminate Session</span>
          </button>
        </header>

        <main className="max-w-7xl mx-auto p-6 space-y-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div className="bg-emerald-500/5 border border-emerald-500/20 p-6 rounded-2xl space-y-2">
              <p className="text-[10px] uppercase tracking-widest opacity-60">Total Users</p>
              <h3 className="text-3xl font-black">{adminUsers.length}</h3>
            </div>
            <div className="bg-emerald-500/5 border border-emerald-500/20 p-6 rounded-2xl space-y-2">
              <p className="text-[10px] uppercase tracking-widest opacity-60">Pending Verifications</p>
              <h3 className="text-3xl font-black text-amber-500">{adminVerifications.filter(v => v.status === 'pending').length}</h3>
            </div>
            <div className="bg-emerald-500/5 border border-emerald-500/20 p-6 rounded-2xl space-y-2">
              <p className="text-[10px] uppercase tracking-widest opacity-60">Active Sessions</p>
              <h3 className="text-3xl font-black">12</h3>
            </div>
            <div className="bg-emerald-500/5 border border-emerald-500/20 p-6 rounded-2xl space-y-2">
              <p className="text-[10px] uppercase tracking-widest opacity-60">System Health</p>
              <h3 className="text-3xl font-black text-emerald-400">OPTIMAL</h3>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="lg:col-span-2 space-y-8">
              <section className="space-y-4">
                <h3 className="text-lg font-bold flex items-center space-x-2">
                  <AlertTriangle size={20} />
                  <span>Pending Death Verifications</span>
                </h3>
                <div className="space-y-4">
                  {adminVerifications.filter(v => v.status === 'pending').map(v => (
                    <div key={v.id} className="bg-emerald-500/5 border border-emerald-500/20 p-6 rounded-2xl flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                      <div className="space-y-1">
                        <h4 className="font-bold text-white">User: {v.user_name}</h4>
                        <p className="text-xs opacity-60">Reported by: {v.beneficiary_name || 'System'}</p>
                        <p className="text-[10px] font-mono opacity-40">CERT_ID: {v.id}</p>
                      </div>
                      <div className="flex space-x-3 w-full md:w-auto">
                        <button 
                          onClick={async () => {
                            const res = await fetch(`/api/admin/verifications/${v.id}/file`, {
                              headers: { Authorization: `Bearer ${adminToken}` }
                            });
                            if (res.ok) {
                              const blob = await res.blob();
                              const url = URL.createObjectURL(blob);
                              window.open(url, '_blank');
                            }
                          }}
                          className="flex-1 md:flex-none px-4 py-2 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 transition-colors flex items-center justify-center space-x-2"
                        >
                          <Eye size={16} />
                          <span>View Cert</span>
                        </button>
                        <button 
                          onClick={async () => {
                            const res = await fetch(`/api/admin/verifications/${v.id}/verify`, {
                              method: 'POST',
                              headers: { Authorization: `Bearer ${adminToken}` }
                            });
                            if (res.ok) fetchAdminData();
                          }}
                          className="flex-1 md:flex-none px-4 py-2 rounded-lg bg-emerald-500 text-black font-bold hover:scale-105 transition-transform flex items-center justify-center space-x-2"
                        >
                          <CheckCircle2 size={16} />
                          <span>Approve Release</span>
                        </button>
                      </div>
                    </div>
                  ))}
                  {adminVerifications.filter(v => v.status === 'pending').length === 0 && (
                    <div className="py-12 text-center border border-dashed border-emerald-500/20 rounded-2xl opacity-40">
                      <p>No pending verifications in queue.</p>
                    </div>
                  )}
                </div>
              </section>

              <section className="space-y-4">
                <h3 className="text-lg font-bold flex items-center space-x-2">
                  <Users size={20} />
                  <span>User Directory</span>
                </h3>
                <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-2xl overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-emerald-500/10 border-b border-emerald-500/20">
                      <tr>
                        <th className="px-6 py-4 font-bold uppercase tracking-widest">Name</th>
                        <th className="px-6 py-4 font-bold uppercase tracking-widest">Email</th>
                        <th className="px-6 py-4 font-bold uppercase tracking-widest">Stage</th>
                        <th className="px-6 py-4 font-bold uppercase tracking-widest">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-emerald-500/10">
                      {adminUsers.map(u => (
                        <tr key={u.id} className="hover:bg-emerald-500/5 transition-colors">
                          <td className="px-6 py-4 font-bold text-white">{u.name}</td>
                          <td className="px-6 py-4 opacity-60">{u.email}</td>
                          <td className="px-6 py-4">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${u.escalation_stage === 'Activation' ? 'bg-rose-500/20 text-rose-400' : 'bg-emerald-500/20 text-emerald-400'}`}>
                              {u.escalation_stage}
                            </span>
                          </td>
                          <td className="px-6 py-4 uppercase opacity-60">{u.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </div>

            <section className="space-y-4">
              <h3 className="text-lg font-bold flex items-center space-x-2">
                <History size={20} />
                <span>System Logs</span>
              </h3>
              <div className="bg-emerald-500/5 border border-emerald-500/20 rounded-2xl p-4 h-[600px] overflow-y-auto font-mono text-[10px] space-y-4">
                {adminLogs.map(log => (
                  <div key={log.id} className="border-l-2 border-emerald-500/20 pl-3 space-y-1">
                    <div className="flex justify-between opacity-40">
                      <span>{new Date(log.created_at).toLocaleTimeString()}</span>
                      <span>{log.type.toUpperCase()}</span>
                    </div>
                    <p className="text-emerald-400 font-bold">{log.subject}</p>
                    <p className="opacity-60 truncate">TO: {log.recipient}</p>
                  </div>
                ))}
                {adminLogs.length === 0 && <p className="opacity-40 italic">No system logs available.</p>}
              </div>
            </section>
          </div>
        </main>
      </div>
    );
  }

  if (beneficiaryToken) {
    return (
      <div className="min-h-screen bg-legacy-blue text-slate-200 font-sans selection:bg-legacy-silver/30">
        <header className="glass sticky top-0 z-50 px-6 py-4 flex justify-between items-center border-b border-white/5">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 silver-gradient rounded-xl flex items-center justify-center shadow-lg shadow-legacy-silver/20">
              <Shield className="text-legacy-blue" size={24} />
            </div>
            <div>
              <h1 className="text-xl font-black tracking-tighter text-white uppercase italic">Legacy-Lock</h1>
              <p className="text-[10px] text-legacy-silver font-mono uppercase tracking-widest">Beneficiary Portal</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button onClick={() => fetchBeneficiaryAssets()} className="p-2 rounded-xl bg-white/5 text-slate-400 hover:text-emerald-400 transition-colors" title="Refresh Assets">
              <RefreshCw size={18} />
            </button>
            <button onClick={handleBeneficiaryLogout} className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-white/5 text-slate-400 hover:text-white transition-colors">
              <LogOut size={18} />
              <span>Exit Portal</span>
            </button>
          </div>
        </header>

        <main className="max-w-6xl mx-auto p-6 space-y-8">
          {beneficiaryAssets?.owner?.escalation_stage && beneficiaryAssets.owner.escalation_stage !== 'Normal' && beneficiaryAssets.owner.escalation_stage !== 'Activation' && (
            <div className="p-8 rounded-3xl bg-amber-500/5 border border-amber-500/10 flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center space-x-6">
                <div className="w-16 h-16 rounded-full bg-amber-500/20 flex items-center justify-center text-amber-400">
                  <AlertTriangle size={32} />
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-white">Continuity Alert: {beneficiaryAssets.owner.name}</h2>
                  <p className="text-slate-400">The system has detected a shift in continuity patterns. Stage: {beneficiaryAssets.owner.escalation_stage}</p>
                </div>
              </div>
              <button 
                onClick={handleBeneficiaryConfirmWellness}
                className="px-8 py-4 rounded-xl bg-amber-500 text-black font-bold shadow-xl shadow-amber-500/20 hover:scale-105 transition-transform"
              >
                Confirm Wellness
              </button>
            </div>
          )}

          {beneficiaryAssets?.owner?.escalation_stage === 'Activation' ? (
            <div className="space-y-8">
              <div className="p-8 rounded-3xl bg-emerald-500/5 border border-emerald-500/10 flex items-center space-x-6">
                <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Zap size={32} />
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-white">Legacy Released</h2>
                  <p className="text-slate-400">The transition has been completed. You can now access the assets shared with you by {beneficiaryAssets.owner.name}.</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div className="md:col-span-2 space-y-8">
                  <section className="space-y-4">
                    <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                      <MessageSquare size={20} className="text-legacy-silver" />
                      <span>Personal Messages</span>
                    </h3>
                    <div className="grid grid-cols-1 gap-4">
                      {beneficiaryAssets?.messages.map(msg => (
                        <div key={msg.id} className="p-6 rounded-2xl bg-white/5 border border-white/5 space-y-4">
                          <div className="flex justify-between items-center">
                            <Badge variant="success">{msg.category}</Badge>
                            <span className="text-[10px] text-slate-500 font-mono">{msg.release_event}</span>
                          </div>
                          <p className="text-slate-300 font-serif italic text-lg leading-relaxed">"{msg.content}"</p>
                        </div>
                      ))}
                      {beneficiaryAssets?.messages.length === 0 && <p className="text-xs text-slate-500 italic">No messages shared with you.</p>}
                    </div>
                  </section>

                  <section className="space-y-4">
                    <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                      <Database size={20} className="text-legacy-silver" />
                      <span>Legacy Assets</span>
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {beneficiaryAssets?.documents.map(doc => (
                        <Card key={doc.id} className="flex items-center justify-between p-4">
                          <div className="flex items-center space-x-3">
                            <div className="p-2 rounded-lg bg-legacy-silver/10 text-legacy-silver">
                              <File size={18} />
                            </div>
                            <div>
                              <h4 className="text-sm font-bold text-white">{doc.title}</h4>
                              <p className="text-[10px] text-slate-500 uppercase">{doc.file_type}</p>
                            </div>
                          </div>
                          <button onClick={() => downloadBeneficiaryAsset(doc)} className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white">
                            <Download size={16} />
                          </button>
                        </Card>
                      ))}
                      {beneficiaryAssets?.documents.length === 0 && <p className="text-xs text-slate-500 italic">No documents shared with you.</p>}
                    </div>
                  </section>
                </div>

                <div className="space-y-8">
                  <section className="space-y-4">
                    <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                      <Lock size={20} className="text-legacy-silver" />
                      <span>Confidential Access</span>
                    </h3>
                    <div className="space-y-4">
                      {beneficiaryAssets?.credentials.map(link => (
                        <div key={link.id} className="p-6 rounded-2xl bg-white/5 border border-white/5 space-y-4">
                          <h4 className="text-sm font-bold text-white">{link.title}</h4>
                          <div className="bg-black/40 p-4 rounded-xl space-y-3 font-mono text-xs">
                            <div className="flex justify-between items-center">
                              <span className="text-slate-500">USERNAME:</span>
                              <span className="text-emerald-400">{link.username}</span>
                            </div>
                            <div className="flex justify-between items-center">
                              <span className="text-slate-500">PASSWORD:</span>
                              <span className="text-emerald-400">{link.password}</span>
                            </div>
                          </div>
                          {link.notes && <p className="text-[10px] text-slate-500 italic">{link.notes}</p>}
                        </div>
                      ))}
                      {beneficiaryAssets?.credentials.length === 0 && <p className="text-xs text-slate-500 italic">No credentials shared with you.</p>}
                    </div>
                  </section>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-12">
              {/* Hero Section */}
              <div className="relative overflow-hidden p-12 text-center glass rounded-[3rem] border border-white/5 space-y-8">
                <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-rose-500/50 to-transparent" />
                <div className="w-24 h-24 bg-white/5 rounded-full flex items-center justify-center mx-auto text-slate-500 relative">
                  <Lock size={48} className="relative z-10" />
                  <div className="absolute inset-0 bg-rose-500/10 blur-2xl rounded-full animate-pulse" />
                </div>
                <div className="space-y-4 relative z-10">
                  <h2 className="text-4xl font-black text-white tracking-tight">Legacy Vault Secured</h2>
                  <p className="text-slate-400 max-w-xl mx-auto text-lg leading-relaxed">
                    {beneficiaryAssets?.owner?.name || 'The owner'} has designated you as a trusted beneficiary. 
                    The shared digital legacy is currently encrypted and will be released upon verified continuity loss.
                  </p>
                </div>

                {/* Primary Action: Upload */}
                <div className="max-w-md mx-auto pt-4 relative z-10">
                  <button 
                    onClick={() => setShowDeathCertModal(true)}
                    className="w-full py-5 rounded-2xl bg-rose-600 text-white font-black shadow-2xl shadow-rose-600/40 hover:bg-rose-500 hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center justify-center space-x-3 group"
                  >
                    <Upload size={24} className="group-hover:bounce" />
                    <span className="text-lg">UPLOAD DEATH CERTIFICATE</span>
                  </button>
                  <p className="mt-4 text-[10px] text-slate-500 uppercase tracking-widest font-bold">Initiate Legacy Release Protocol</p>
                </div>
                
                {/* Transition Roadmap */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 max-w-3xl mx-auto pt-8 border-t border-white/5">
                  <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-2">
                    <div className="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto text-xs font-bold">01</div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Request Access</p>
                    <p className="text-[11px] text-slate-400">Submit documentation for review.</p>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-2 opacity-50">
                    <div className="w-8 h-8 rounded-full bg-white/10 text-white flex items-center justify-center mx-auto text-xs font-bold">02</div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Verification</p>
                    <p className="text-[11px] text-slate-400">Admin review of certificate.</p>
                  </div>
                  <div className="p-4 rounded-2xl bg-white/5 border border-white/5 space-y-2 opacity-50">
                    <div className="w-8 h-8 rounded-full bg-white/10 text-white flex items-center justify-center mx-auto text-xs font-bold">03</div>
                    <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Legacy Release</p>
                    <p className="text-[11px] text-slate-400">Full vault decryption.</p>
                  </div>
                </div>
              </div>

              {/* Interactive Section */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 space-y-8">
                  {/* Pre-Verification Inventory */}
                  <section className="space-y-6">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold text-legacy-silver uppercase tracking-[0.2em] flex items-center space-x-2">
                        <Database size={16} />
                        <span>Encrypted Asset Inventory</span>
                      </h3>
                      <div className="flex items-center space-x-2 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/20">
                        <Lock size={12} className="text-rose-400" />
                        <span className="text-[10px] font-bold text-rose-400 uppercase tracking-widest">Locked</span>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      {beneficiaryAssets?.messages.map((m, i) => (
                        <div key={i} className="p-6 rounded-2xl bg-white/5 border border-white/5 space-y-3 opacity-40 grayscale blur-[1px]">
                          <div className="flex justify-between items-center">
                            <div className="w-8 h-8 rounded-lg bg-white/5 flex items-center justify-center">
                              <MessageSquare size={14} className="text-slate-500" />
                            </div>
                            <span className="text-[10px] font-mono text-slate-600">ENCRYPTED_MSG_{i+1}</span>
                          </div>
                          <div className="space-y-2">
                            <div className="h-2 w-full bg-white/10 rounded" />
                            <div className="h-2 w-2/3 bg-white/10 rounded" />
                          </div>
                        </div>
                      ))}
                      {beneficiaryAssets?.documents.map((d, i) => (
                        <div key={i} className="p-4 rounded-xl bg-white/5 border border-white/5 flex items-center space-x-4 opacity-40 grayscale blur-[1px]">
                          <div className="w-10 h-10 rounded-lg bg-white/5 flex items-center justify-center">
                            <File size={18} className="text-slate-500" />
                          </div>
                          <div className="flex-1 space-y-2">
                            <p className="text-xs font-bold text-slate-600 italic">Encrypted Document</p>
                            <div className="h-1.5 w-1/2 bg-white/10 rounded" />
                          </div>
                          <Lock size={14} className="text-slate-800" />
                        </div>
                      ))}
                    </div>
                  </section>

                  {/* Verification Status */}
                  {beneficiaryAssets?.verifications && beneficiaryAssets.verifications.length > 0 && (
                    <section className="space-y-4">
                      <h3 className="text-sm font-bold text-white uppercase tracking-wider">Active Transition Requests</h3>
                      <div className="space-y-3">
                        {beneficiaryAssets.verifications.map(v => (
                          <div key={v.id} className="flex items-center justify-between p-6 bg-black/40 rounded-2xl border border-white/5">
                            <div className="flex items-center space-x-4">
                              <div className={`w-12 h-12 rounded-full flex items-center justify-center ${v.status === 'verified' ? 'bg-emerald-500/20 text-emerald-400' : v.status === 'rejected' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400 animate-pulse'}`}>
                                {v.status === 'verified' ? <CheckCircle2 size={24} /> : v.status === 'rejected' ? <X size={24} /> : <Clock size={24} />}
                              </div>
                              <div>
                                <p className="font-bold text-white">Death Certificate Verification</p>
                                <p className="text-xs text-slate-500">Submitted on {new Date(v.created_at).toLocaleDateString()}</p>
                              </div>
                            </div>
                            <Badge variant={v.status === 'verified' ? 'success' : v.status === 'rejected' ? 'danger' : 'warning'}>
                              {v.status.toUpperCase()}
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </section>
                  )}
                </div>

                <div className="space-y-8">
                  {/* Action Card */}
                  <Card className="p-8 space-y-6 relative overflow-hidden border-rose-500/20 bg-rose-500/5">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-rose-500/10 blur-3xl rounded-full -mr-16 -mt-16" />
                    <div className="space-y-2 relative z-10">
                      <h3 className="text-xl font-bold text-white flex items-center space-x-2">
                        <AlertTriangle className="text-rose-400" size={24} />
                        <span>Request Access</span>
                      </h3>
                      <p className="text-sm text-slate-400 leading-relaxed">
                        If you have the required documentation, you can request manual review from the Legacy-Lock administration team.
                      </p>
                    </div>
                    <button 
                      onClick={() => setShowDeathCertModal(true)}
                      className="w-full py-4 rounded-2xl bg-white/5 border border-white/10 text-white font-bold hover:bg-white/10 transition-all flex items-center justify-center space-x-3"
                    >
                      <FileText size={20} />
                      <span>Submit Documentation</span>
                    </button>
                    <div className="p-4 rounded-xl bg-white/5 border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-2">Required Info</p>
                      <ul className="space-y-2">
                        <li className="flex items-center space-x-2 text-[11px] text-slate-400">
                          <CheckCircle2 size={12} className="text-emerald-500" />
                          <span>Official Death Certificate (PDF/JPG)</span>
                        </li>
                        <li className="flex items-center space-x-2 text-[11px] text-slate-400">
                          <CheckCircle2 size={12} className="text-emerald-500" />
                          <span>Beneficiary Identity Confirmation</span>
                        </li>
                      </ul>
                    </div>
                  </Card>

                  {/* Support/Info Card */}
                  <Card className="p-6 bg-legacy-silver/5 border-legacy-silver/10 space-y-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 rounded-xl bg-legacy-silver/10 flex items-center justify-center text-legacy-silver">
                        <Activity size={20} />
                      </div>
                      <h4 className="font-bold text-white">System Status</h4>
                    </div>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-500">Continuity Engine:</span>
                        <span className="text-emerald-400 font-mono">ACTIVE</span>
                      </div>
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-500">Encryption Layer:</span>
                        <span className="text-emerald-400 font-mono">AES-256-GCM</span>
                      </div>
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-500">Release Protocol:</span>
                        <span className="text-slate-300 font-mono">MULTI-SIG PENDING</span>
                      </div>
                    </div>
                  </Card>

                  {/* Legacy Assistant */}
                  <Card className="p-6 space-y-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                        <MessageSquare size={20} />
                      </div>
                      <div>
                        <h4 className="font-bold text-white">Legacy Assistant</h4>
                        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">AI Support</p>
                      </div>
                    </div>
                    <div className="bg-black/40 p-4 rounded-xl text-xs text-slate-300 leading-relaxed italic">
                      "Hello. I am the Digital Continuity Assistant. I can help you understand the verification process or guide you through the transition steps. How can I assist you today?"
                    </div>
                    <div className="flex gap-2">
                      <button className="flex-1 py-2 rounded-lg bg-white/5 border border-white/5 text-[10px] text-slate-400 hover:text-white transition-colors">Process Info</button>
                      <button className="flex-1 py-2 rounded-lg bg-white/5 border border-white/5 text-[10px] text-slate-400 hover:text-white transition-colors">Legal FAQ</button>
                    </div>
                  </Card>
                </div>
              </div>
            </div>
          )}
        </main>
        <footer className="max-w-6xl mx-auto p-6 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4 text-[10px] text-slate-500 uppercase tracking-widest font-bold">
          <div className="flex items-center space-x-6">
            <a href="#" className="hover:text-white transition-colors">Privacy Protocol</a>
            <a href="#" className="hover:text-white transition-colors">Security Audit</a>
            <a href="#" className="hover:text-white transition-colors">Legal Framework</a>
          </div>
          <p>© 2026 Legacy-Lock Digital Continuity Engine</p>
        </footer>
      </div>
    );
  }

  if (!token) {
    return (
      <div className="min-h-screen bg-legacy-blue flex items-center justify-center p-6 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-legacy-blue via-black to-black">
        <div className="w-full max-w-md space-y-8">
          <div className="text-center space-y-4">
            <div className="w-20 h-20 silver-gradient rounded-3xl flex items-center justify-center mx-auto shadow-2xl shadow-legacy-silver/20 rotate-3">
              <Shield className="text-legacy-blue" size={48} />
            </div>
            <div>
              <h1 className="text-4xl font-black tracking-tighter text-white uppercase italic">Legacy-Lock</h1>
              <p className="text-legacy-silver font-mono text-xs uppercase tracking-[0.3em] mt-2">Digital Continuity Engine</p>
            </div>
          </div>

          <div className="glass rounded-[2.5rem] p-8 shadow-2xl border border-white/5">
            <div className="flex p-1 bg-white/5 rounded-2xl mb-8">
              <button 
                onClick={() => { setIsBeneficiaryMode(false); setIsAdminMode(false); }}
                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all ${(!isBeneficiaryMode && !isAdminMode) ? 'bg-legacy-silver text-legacy-blue shadow-lg' : 'text-slate-400 hover:text-white'}`}
              >
                Owner
              </button>
              <button 
                onClick={() => { setIsBeneficiaryMode(true); setIsAdminMode(false); }}
                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all ${isBeneficiaryMode ? 'bg-legacy-silver text-legacy-blue shadow-lg' : 'text-slate-400 hover:text-white'}`}
              >
                Beneficiary
              </button>
              <button 
                onClick={() => { setIsAdminMode(true); setIsBeneficiaryMode(false); }}
                className={`flex-1 py-3 rounded-xl text-sm font-bold transition-all ${isAdminMode ? 'bg-emerald-500 text-black shadow-lg' : 'text-slate-400 hover:text-white'}`}
              >
                Server
              </button>
            </div>

            {isAdminMode ? (
              <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }}>
                <form onSubmit={handleAdminLogin} className="space-y-6">
                  <div className="space-y-1">
                    <label className="text-[10px] font-bold text-emerald-500 uppercase ml-1">Admin Identifier</label>
                    <input 
                      type="email" 
                      required 
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      className="w-full bg-black/40 border border-emerald-500/20 rounded-2xl px-5 py-4 text-emerald-400 font-mono focus:outline-none focus:border-emerald-500/50 transition-colors"
                      placeholder="admin@2026"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] font-bold text-emerald-500 uppercase ml-1">Access Key</label>
                    <input 
                      type="password" 
                      required 
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      className="w-full bg-black/40 border border-emerald-500/20 rounded-2xl px-5 py-4 text-emerald-400 font-mono focus:outline-none focus:border-emerald-500/50 transition-colors"
                      placeholder="••••••••"
                    />
                  </div>

                  {adminError && <p className="text-rose-500 text-xs text-center font-bold">{adminError}</p>}

                  <button 
                    type="submit"
                    className="w-full py-5 rounded-2xl bg-emerald-500 text-black font-black uppercase tracking-widest shadow-xl shadow-emerald-500/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
                  >
                    Initialize Server Console
                  </button>
                  <p className="text-center text-[10px] text-slate-500 leading-relaxed font-mono">
                    Simulation Admin: admin@2026 / 12345
                  </p>
                </form>
              </motion.div>
            ) : !isBeneficiaryMode ? (
              <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}>
                {!isAuthBiometricStep ? (
                  <form onSubmit={handleAuth} className="space-y-4">
                    {!isLogin && (
                      <div className="space-y-1">
                        <label className="text-xs font-bold text-slate-500 uppercase ml-1">Full Name</label>
                        <input 
                          type="text" 
                          value={name} 
                          onChange={e => setName(e.target.value)}
                          className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                          placeholder="Alex Sterling"
                          required
                        />
                      </div>
                    )}
                    <div className="space-y-1">
                      <label className="text-xs font-bold text-slate-500 uppercase ml-1">Email Address</label>
                      <input 
                        type="email" 
                        value={email} 
                        onChange={e => setEmail(e.target.value)}
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                        placeholder="alex@example.com"
                        required
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-xs font-bold text-slate-500 uppercase ml-1">Password</label>
                      <input 
                        type="password" 
                        value={password} 
                        onChange={e => setPassword(e.target.value)}
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                        placeholder="••••••••"
                        required
                      />
                    </div>

                    {authError && <p className="text-rose-400 text-sm text-center">{authError}</p>}

                    <button type="submit" className="w-full silver-gradient text-legacy-blue font-bold py-4 rounded-xl shadow-lg shadow-legacy-silver/20 hover:scale-[1.02] transition-transform flex items-center justify-center space-x-2">
                      <span>Continue to Biometrics</span>
                      <ArrowRight size={18} />
                    </button>
                  </form>
                ) : (
                  <div className="space-y-6">
                    <div className="text-center space-y-2">
                      <h3 className="text-xl font-bold text-white">Face Verification</h3>
                      <p className="text-sm text-slate-400">Please verify your identity to complete {isLogin ? 'login' : 'registration'}.</p>
                    </div>

                    <div className="relative aspect-square max-w-[240px] mx-auto bg-slate-900 rounded-full overflow-hidden border-4 border-white/10 shadow-2xl">
                      {!cameraStream ? (
                        <div className="absolute inset-0 flex flex-col items-center justify-center space-y-4">
                          <div className="w-16 h-16 rounded-full bg-white/5 animate-pulse flex items-center justify-center">
                            <UserIcon size={32} className="text-slate-700" />
                          </div>
                          <p className="text-[10px] text-slate-500 uppercase tracking-widest">Initializing Camera...</p>
                        </div>
                      ) : (
                        <>
                          <video 
                            ref={authVideoRef} 
                            autoPlay 
                            playsInline 
                            muted 
                            className="w-full h-full object-cover scale-x-[-1]"
                          />
                          <div className="absolute inset-0 pointer-events-none">
                            <motion.div 
                              initial={{ top: '0%' }}
                              animate={{ top: '100%' }}
                              transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                              className="absolute left-0 right-0 h-0.5 bg-legacy-silver/50 shadow-[0_0_15px_rgba(192,192,192,0.8)] z-10"
                            />
                            <div className="absolute inset-0 border-[20px] border-legacy-blue/40 rounded-full"></div>
                            <div className="absolute inset-0 flex items-center justify-center">
                              <div className="w-48 h-48 border border-white/20 rounded-full border-dashed animate-[spin_10s_linear_infinite]"></div>
                            </div>
                          </div>
                        </>
                      )}
                      {isVerifying && (
                        <div className="absolute inset-0 bg-legacy-blue/60 backdrop-blur-sm flex flex-col items-center justify-center space-y-4 z-20">
                          <div className="w-12 h-12 border-4 border-legacy-silver border-t-transparent rounded-full animate-spin"></div>
                          <p className="text-legacy-silver font-mono text-[10px] animate-pulse tracking-[0.2em]">ANALYZING BIOMETRICS...</p>
                        </div>
                      )}
                    </div>

                    <div className="flex space-x-3">
                      <button 
                        onClick={() => { setIsAuthBiometricStep(false); stopCamera(); }}
                        className="flex-1 py-3 rounded-xl bg-white/5 text-slate-400 font-bold"
                        disabled={isVerifying}
                      >
                        Back
                      </button>
                      <button 
                        onClick={handleAuth}
                        disabled={!cameraStream || isVerifying}
                        className="flex-1 py-3 rounded-xl silver-gradient text-legacy-blue font-bold shadow-lg shadow-legacy-silver/20 disabled:opacity-50 transition-all"
                      >
                        {isLogin ? 'Verify & Login' : 'Verify & Register'}
                      </button>
                    </div>
                  </div>
                )}
              </motion.div>
            ) : (
              <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}>
                <form onSubmit={handleBeneficiaryLogin} className="space-y-6">
                  <div className="space-y-1">
                    <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Registered Email</label>
                    <input 
                      type="email" 
                      required 
                      value={beneficiaryEmail}
                      onChange={e => setBeneficiaryEmail(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-white focus:outline-none focus:border-legacy-silver/50 transition-colors"
                      placeholder="your@email.com"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-[10px] font-bold text-slate-500 uppercase ml-1">Password</label>
                    <input 
                      type="password" 
                      required 
                      value={beneficiaryPassword}
                      onChange={e => setBeneficiaryPassword(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-2xl px-5 py-4 text-white focus:outline-none focus:border-legacy-silver/50 transition-colors"
                      placeholder="Enter or set your password"
                    />
                  </div>

                  {beneficiaryError && <p className="text-rose-500 text-xs text-center font-bold">{beneficiaryError}</p>}

                  <button 
                    type="submit"
                    className="w-full py-5 rounded-2xl silver-gradient text-legacy-blue font-black uppercase tracking-widest shadow-xl shadow-legacy-silver/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
                  >
                    Access Legacy Portal
                  </button>
                  <p className="text-center text-[10px] text-slate-500 leading-relaxed">
                    First-time login? Simply enter your email and the password you wish to use.
                  </p>
                  
                  <div className="pt-4 border-t border-white/5">
                    <button 
                      onClick={() => { setIsAdminMode(true); setIsBeneficiaryMode(false); }}
                      className="w-full text-[10px] text-slate-600 hover:text-emerald-500 uppercase tracking-widest font-bold transition-colors"
                    >
                      System Administrator Access
                    </button>
                  </div>
                </form>
              </motion.div>
            )}

            <div className="text-center mt-6">
              <button 
                onClick={() => { setIsLogin(!isLogin); setIsAuthBiometricStep(false); stopCamera(); }}
                className="text-slate-400 text-sm hover:text-white transition-colors"
              >
                {!isBeneficiaryMode && (isLogin ? "Don't have an account? Register" : "Already have an account? Login")}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const filteredDocs = selectedSectionId 
    ? documents.filter(d => d.section_id === selectedSectionId)
    : documents;

  return (
    <div className="min-h-screen flex bg-legacy-blue text-slate-200 overflow-hidden">
      {/* Sidebar */}
      <aside className={`
        fixed inset-y-0 left-0 w-64 border-r border-white/5 p-6 flex flex-col space-y-8 bg-legacy-blue z-50 transition-transform duration-300 lg:relative lg:translate-x-0
        ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'}
      `}>
        <div className="flex items-center justify-between lg:justify-start lg:space-x-3 px-2">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 silver-gradient rounded-xl flex items-center justify-center shadow-lg shadow-legacy-silver/20">
              <Shield className="text-legacy-blue" size={24} />
            </div>
            <h1 className="text-xl font-serif font-bold tracking-tight">Legacy-Lock</h1>
          </div>
          <button onClick={() => setIsSidebarOpen(false)} className="lg:hidden text-slate-400">
            <X size={24} />
          </button>
        </div>

          <nav className="flex-1 space-y-2">
            <SidebarItem icon={Activity} label="Dashboard" active={activeTab === 'dashboard'} onClick={() => { setActiveTab('dashboard'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={Lock} label="Secure Vault" active={activeTab === 'vault'} onClick={() => { setActiveTab('vault'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={Users} label="Trust Network" active={activeTab === 'contacts'} onClick={() => { setActiveTab('contacts'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={MessageSquare} label="Legacy Messages" active={activeTab === 'messages'} onClick={() => { setActiveTab('messages'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={Database} label="Confidential Sharing" active={activeTab === 'confidential'} onClick={() => { setActiveTab('confidential'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={FileText} label="Continuity Plan" active={activeTab === 'will'} onClick={() => { setActiveTab('will'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={Cpu} label="Continuity Engine" active={activeTab === 'engine'} onClick={() => { setActiveTab('engine'); setIsSidebarOpen(false); }} />
            <SidebarItem icon={Zap} label="Legacy Simulation" active={activeTab === 'simulation'} onClick={() => { setActiveTab('simulation'); setIsSidebarOpen(false); }} />
          </nav>

        <div className="space-y-4">
          <div className="glass rounded-2xl p-4 space-y-3">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-full bg-white/5 flex items-center justify-center">
                <UserIcon size={16} className="text-slate-400" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-white truncate">{user?.name}</p>
                <p className="text-[10px] text-slate-500 truncate">{user?.email}</p>
              </div>
              <button onClick={handleLogout} className="text-slate-500 hover:text-rose-400 transition-colors">
                <LogOut size={16} />
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto p-4 md:p-8">
        <header className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 space-y-4 md:space-y-0">
          <div className="flex items-center space-x-4">
            <button onClick={() => setIsSidebarOpen(true)} className="lg:hidden p-2 bg-white/5 rounded-lg text-slate-400">
              <Menu size={24} />
            </button>
            <div>
              <h2 className="text-2xl md:text-3xl font-serif font-bold text-white">
                {activeTab === 'dashboard' && `Continuity Intelligence`}
                {activeTab === 'vault' && 'Secure Legacy Vault'}
                {activeTab === 'contacts' && 'Trust Network'}
                {activeTab === 'messages' && 'Emotional Continuity'}
                {activeTab === 'confidential' && 'Confidential Credential Sharing'}
                {activeTab === 'will' && 'Life Continuity Plan'}
                {activeTab === 'engine' && 'Continuity Assurance Engine™'}
                {activeTab === 'simulation' && 'Legacy Release Simulation'}
              </h2>
              <p className="text-slate-400 mt-1 text-sm md:text-base">
                {activeTab === 'dashboard' && 'Monitor your digital estate readiness.'}
                {activeTab === 'vault' && 'Manage your encrypted legacy assets.'}
                {activeTab === 'contacts' && 'Your circle of trusted continuity partners.'}
                {activeTab === 'messages' && 'Schedule milestone blessings and reflections.'}
                {activeTab === 'confidential' && 'Securely share credentials with your trust network.'}
                {activeTab === 'will' && 'AI-driven legal adaptation for your legacy.'}
                {activeTab === 'engine' && 'Multi-stage legacy activation settings.'}
                {activeTab === 'simulation' && 'Preview the legacy package for your beneficiaries.'}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4 w-full md:w-auto">
            <div className="relative">
              <button 
                onClick={() => setShowNotifications(!showNotifications)}
                className="p-2.5 rounded-full bg-white/5 border border-white/10 text-slate-400 hover:text-white transition-colors relative"
              >
                <Bell size={20} />
                {notifications.some(n => !n.is_read) && (
                  <span className="absolute top-0 right-0 w-3 h-3 bg-rose-500 rounded-full border-2 border-legacy-blue"></span>
                )}
              </button>
              
              <AnimatePresence>
                {showNotifications && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 10 }}
                    className="absolute right-0 mt-4 w-80 glass rounded-2xl p-4 shadow-2xl z-[60] space-y-4"
                  >
                    <div className="flex justify-between items-center border-b border-white/5 pb-2">
                      <h4 className="font-bold text-white text-sm">Notifications</h4>
                      <button 
                        onClick={async () => {
                          await fetch('/api/notifications/read', { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
                          fetchAll();
                        }}
                        className="text-[10px] text-legacy-silver hover:underline"
                      >
                        Mark all as read
                      </button>
                    </div>
                    <div className="max-h-60 overflow-y-auto space-y-2">
                      {notifications.map(n => (
                        <div key={n.id} className={`p-3 rounded-xl ${n.is_read ? 'bg-white/5' : 'bg-white/10 border border-white/10'} space-y-1`}>
                          <div className="flex items-center space-x-2">
                            <div className={`w-2 h-2 rounded-full ${n.type === 'alert' ? 'bg-rose-500' : n.type === 'warning' ? 'bg-amber-500' : 'bg-legacy-silver'}`}></div>
                            <h5 className="text-xs font-bold text-white">{n.title}</h5>
                          </div>
                          <p className="text-[10px] text-slate-400 leading-relaxed">{n.message}</p>
                        </div>
                      ))}
                      {notifications.length === 0 && <p className="text-center py-4 text-xs text-slate-500">No notifications.</p>}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <button 
              onClick={handleCheckIn}
              className={`flex-1 md:flex-none flex items-center justify-center space-x-2 px-6 py-2.5 rounded-full font-bold shadow-lg transition-all ${escalationStage !== 'Normal' ? 'bg-rose-500 text-white animate-pulse shadow-rose-500/20' : 'silver-gradient text-legacy-blue shadow-legacy-silver/20 hover:scale-105'}`}
            >
              <Zap size={18} />
              <span>{escalationStage !== 'Normal' ? 'Confirm Status' : 'Check In'}</span>
            </button>
            <button 
              onClick={() => setShowJuryBrief(true)}
              className="flex-1 md:flex-none flex items-center justify-center space-x-2 px-4 py-2.5 rounded-full bg-white/5 border border-white/10 text-slate-400 hover:text-white transition-colors"
            >
              <Eye size={18} />
              <span>Project Brief</span>
            </button>
          </div>
        </header>

        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
          >
            {activeTab === 'dashboard' && (
              <div className="space-y-8">
                {/* Continuity Status Banner */}
                <div className={`p-6 rounded-3xl border flex flex-col md:flex-row items-center justify-between gap-6 ${escalationStage === 'Normal' ? 'bg-emerald-500/5 border-emerald-500/10' : 'bg-rose-500/5 border-rose-500/10'}`}>
                  <div className="flex items-center space-x-4">
                    <div className={`w-12 h-12 rounded-full flex items-center justify-center ${escalationStage === 'Normal' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-rose-500/20 text-rose-400'}`}>
                      <Shield size={24} />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white">System Status: {escalationStage}</h3>
                      <p className="text-xs text-slate-400">
                        {escalationStage === 'Normal' ? 'Your legacy is secure and monitored. No action required.' : 'Escalation protocol active. Please check in immediately.'}
                      </p>
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    {['Normal', 'Reminder', 'Wellness', 'Circle', 'Activation'].map(s => (
                      <button 
                        key={s}
                        onClick={() => simulateEscalation(s)}
                        className={`px-3 py-1 rounded-lg text-[10px] font-mono border transition-all ${escalationStage === s ? 'bg-legacy-silver text-legacy-blue border-legacy-silver' : 'bg-white/5 border-white/10 text-slate-500 hover:text-white'}`}
                      >
                        {s.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="md:col-span-2 flex flex-col justify-between">
                  <div className="flex justify-between items-start mb-6">
                    <div>
                      <h3 className="text-lg font-bold text-white flex items-center space-x-2">
                        <Zap className="text-legacy-silver" size={20} />
                        <span>Life Continuity Mode™</span>
                      </h3>
                      <div className="flex items-center space-x-2 mt-1">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></div>
                        <p className="text-slate-400 text-sm">Status: Active & Reassured</p>
                      </div>
                    </div>
                    <Badge variant="success">Secured</Badge>
                  </div>
                  <div className="space-y-4">
                    <div className="flex justify-between text-[10px] text-slate-500 font-mono mb-1">
                      <span>CONTINUITY CONFIDENCE</span>
                      <span>98%</span>
                    </div>
                    <div className="w-full bg-white/5 h-2 rounded-full overflow-hidden">
                      <div className="bg-legacy-silver h-full w-[98%] shadow-[0_0_10px_rgba(192,192,192,0.5)]"></div>
                    </div>
                    <div className="flex justify-between text-[10px] text-slate-500 font-mono">
                      <span>LAST CONFIRMATION: {user?.last_check_in ? new Date(user.last_check_in).toLocaleDateString() : 'TODAY'}</span>
                      <span>NEXT STAGE: {escalationConfig.reminderDays} DAYS</span>
                    </div>
                  </div>
                </Card>

                <Card className="flex flex-col items-center justify-center text-center space-y-4">
                  <div className="w-16 h-16 rounded-full bg-emerald-500/10 flex items-center justify-center text-emerald-400">
                    <Award size={32} />
                  </div>
                  <div>
                    <h4 className="font-bold text-white">Readiness Score</h4>
                    <p className="text-slate-400 text-sm">Legacy Prepared</p>
                  </div>
                  <button 
                    onClick={handleAnalyzeRisk}
                    disabled={isAnalyzingRisk}
                    className="text-[10px] uppercase tracking-widest text-legacy-silver hover:text-white transition-colors flex items-center space-x-1"
                  >
                    <BarChart3 size={12} />
                    <span>{isAnalyzingRisk ? 'Analyzing...' : 'Continuity Audit'}</span>
                  </button>
                </Card>

                <div className="md:col-span-3 grid grid-cols-1 md:grid-cols-4 gap-4">
                  <Card className="p-4 flex flex-col space-y-2">
                    <div className="flex justify-between items-center">
                      <Shield size={18} className="text-legacy-silver" />
                      <span className="text-[10px] font-mono text-emerald-400">100%</span>
                    </div>
                    <p className="text-xs font-bold text-white">Encryption Strength</p>
                    <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden">
                      <div className="bg-emerald-500 h-full w-full"></div>
                    </div>
                  </Card>
                  <Card className="p-4 flex flex-col space-y-2">
                    <div className="flex justify-between items-center">
                      <UserIcon size={18} className="text-legacy-silver" />
                      <span className="text-[10px] font-mono text-emerald-400">100%</span>
                    </div>
                    <p className="text-xs font-bold text-white">Biometric Security</p>
                    <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden">
                      <div className="bg-emerald-500 h-full w-full"></div>
                    </div>
                  </Card>
                  <Card className="p-4 flex flex-col space-y-2">
                    <div className="flex justify-between items-center">
                      <Database size={18} className="text-legacy-silver" />
                      <span className="text-[10px] font-mono text-amber-400">85%</span>
                    </div>
                    <p className="text-xs font-bold text-white">Vault Completion</p>
                    <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden">
                      <div className="bg-amber-500 h-full w-[85%]"></div>
                    </div>
                  </Card>
                  <Card className="p-4 flex flex-col space-y-2">
                    <div className="flex justify-between items-center">
                      <Users size={18} className="text-legacy-silver" />
                      <span className="text-[10px] font-mono text-emerald-400">92%</span>
                    </div>
                    <p className="text-xs font-bold text-white">Trust Network Strength</p>
                    <div className="w-full bg-white/5 h-1 rounded-full overflow-hidden">
                      <div className="bg-emerald-500 h-full w-[92%]"></div>
                    </div>
                  </Card>
                </div>

                <Card className="md:col-span-3">
                  <div className="flex justify-between items-center mb-8">
                    <h4 className="font-bold text-white flex items-center space-x-2">
                      <History size={18} className="text-legacy-silver" />
                      <span>Legacy Continuity Roadmap</span>
                    </h4>
                    <Badge variant="success">System Operational</Badge>
                  </div>
                  
                  <div className="relative">
                    <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-white/5 -translate-y-1/2 hidden md:block"></div>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-8 relative z-10">
                      {[
                        { step: '01', title: 'Asset Encryption', icon: Lock, status: 'Complete', desc: 'Documents are AES-256 encrypted and stored in the vault.' },
                        { step: '02', title: 'Trust Assignment', icon: Users, status: 'Active', desc: 'Assets are assigned to verified continuity partners.' },
                        { step: '03', title: 'Continuity Monitoring', icon: Activity, status: 'Monitoring', desc: 'System tracks check-ins and life patterns via AI.' },
                        { step: '04', title: 'Graceful Release', icon: Zap, status: 'Standby', desc: 'Legacy is transitioned to beneficiaries upon activation.' }
                      ].map((item, i) => (
                        <div key={i} className="flex flex-col items-center text-center space-y-4">
                          <div className={`w-12 h-12 rounded-full flex items-center justify-center border-2 ${i < 3 ? 'bg-legacy-blue border-legacy-silver text-legacy-silver' : 'bg-white/5 border-white/10 text-slate-600'}`}>
                            <item.icon size={20} />
                          </div>
                          <div>
                            <p className="text-[10px] font-mono text-legacy-silver mb-1">{item.step}</p>
                            <h5 className="text-sm font-bold text-white">{item.title}</h5>
                            <p className="text-[10px] text-slate-500 mt-2 leading-relaxed">{item.desc}</p>
                          </div>
                          <Badge variant={i < 3 ? 'success' : 'default'}>{item.status}</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </Card>

                <Card className="md:col-span-3">
                  <div className="flex justify-between items-center mb-6">
                    <h4 className="font-bold text-white flex items-center space-x-2">
                      <Cpu size={18} className="text-legacy-silver" />
                      <span>Vault Optimization Engine</span>
                    </h4>
                    <button 
                      onClick={handleScanVault}
                      disabled={isScanningVault}
                      className="text-[10px] uppercase tracking-widest bg-white/5 px-3 py-1.5 rounded-lg hover:bg-white/10 transition-colors"
                    >
                      {isScanningVault ? 'Scanning...' : 'Run Optimization Scan'}
                    </button>
                  </div>
                  
                  {vaultInsights ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {vaultInsights.enhancementTips.map((tip: any, i: number) => (
                        <div key={i} className="p-4 rounded-xl bg-white/5 border border-white/5 hover:border-legacy-silver/20 transition-all">
                          <div className="flex justify-between items-start mb-2">
                            <h5 className="text-sm font-bold text-white">{tip.title}</h5>
                            <Badge variant="success">Tip</Badge>
                          </div>
                          <p className="text-xs text-slate-400">{tip.description}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-10 border border-dashed border-white/10 rounded-2xl">
                      <p className="text-sm text-slate-500">Run a scan to discover vault enhancement opportunities.</p>
                    </div>
                  )}
                </Card>
              </div>
            </div>
          )}

            {activeTab === 'vault' && (
              <div className="space-y-6">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center space-y-4 md:space-y-0">
                  <div className="flex flex-wrap gap-2">
                    <button 
                      onClick={() => setSelectedSectionId(null)}
                      className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors ${!selectedSectionId ? 'bg-legacy-silver text-legacy-blue' : 'bg-white/5 text-slate-400 hover:bg-white/10'}`}
                    >
                      All
                    </button>
                    {sections.map(sec => (
                      <div key={sec.id} className="relative group">
                        <button 
                          onClick={() => setSelectedSectionId(sec.id)}
                          className={`px-4 py-1.5 rounded-full text-sm font-medium transition-colors ${selectedSectionId === sec.id ? 'bg-legacy-silver text-legacy-blue' : 'bg-white/5 text-slate-400 hover:bg-white/10'}`}
                        >
                          {sec.name}
                        </button>
                        <button 
                          onClick={() => deleteSection(sec.id)}
                          className="absolute -top-1 -right-1 w-4 h-4 bg-rose-500 text-white rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <X size={10} />
                        </button>
                      </div>
                    ))}
                    <button 
                      onClick={() => setShowAddSection(true)}
                      className="w-8 h-8 rounded-full bg-white/5 flex items-center justify-center text-slate-400 hover:bg-white/10 transition-colors"
                    >
                      <Plus size={16} />
                    </button>
                  </div>
                  
                  {selectedSectionId && (
                    <button 
                      onClick={() => setShowUpload(true)}
                      className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors w-full md:w-auto justify-center"
                    >
                      <Upload size={18} />
                      <span>Upload to {sections.find(s => s.id === selectedSectionId)?.name}</span>
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {filteredDocs.map((doc) => (
                    <Card key={doc.id} className="group hover:border-legacy-silver/30 transition-all">
                      <div className="flex justify-between items-start">
                        <div className="flex items-center space-x-4">
                          <div className="p-3 rounded-xl bg-legacy-silver/10 text-legacy-silver">
                            <File size={20} />
                          </div>
                          <div>
                            <h4 className="font-bold text-white truncate max-w-[150px]">{doc.title}</h4>
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest mt-0.5">
                              {sections.find(s => s.id === doc.section_id)?.name}
                            </p>
                          </div>
                        </div>
                        <div className="flex flex-col items-end space-y-2">
                          <Badge variant={PriorityColors[doc.priority]}>{doc.priority}</Badge>
                          <div className="flex space-x-1">
                            <select 
                              value={doc.priority}
                              onChange={(e) => updatePriority(doc.id, e.target.value as any)}
                              className="bg-transparent text-[10px] text-slate-500 focus:outline-none"
                            >
                              <option value="High">High</option>
                              <option value="Medium">Medium</option>
                              <option value="Low">Low</option>
                            </select>
                          </div>
                        </div>
                      </div>
                      
                      <div className="mt-6 flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <button 
                            onClick={() => downloadDocument(doc)}
                            className="p-1.5 rounded-lg bg-white/5 text-slate-400 hover:text-white transition-colors"
                          >
                            <Download size={14} />
                          </button>
                          <button 
                            onClick={() => handlePreview(doc)}
                            className="p-1.5 rounded-lg bg-white/5 text-slate-400 hover:text-white transition-colors"
                          >
                            <Eye size={14} />
                          </button>
                          <button 
                            onClick={() => deleteDocument(doc.id)}
                            className="p-1.5 rounded-lg bg-white/5 text-slate-400 hover:text-rose-400 transition-colors"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                        <span className="text-[10px] text-slate-600 font-mono">ID: {doc.id.slice(0, 8)}</span>
                      </div>
                    </Card>
                  ))}

                  {filteredDocs.length === 0 && (
                    <div className="md:col-span-2 lg:col-span-3 py-20 text-center space-y-4">
                      <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center mx-auto text-slate-600">
                        <Database size={32} />
                      </div>
                      <p className="text-slate-400">No documents found in this section.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'contacts' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-xl font-bold text-white">Trust Network</h3>
                  <button 
                    onClick={() => setShowAddContact(true)}
                    className="flex items-center space-x-2 px-4 py-2 rounded-xl silver-gradient text-legacy-blue font-bold"
                  >
                    <Plus size={18} />
                    <span>Add Partner</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {contacts.map(contact => (
                    <Card key={contact.id} className="relative group">
                      <div className="flex items-center space-x-4">
                        <div className="w-12 h-12 rounded-full bg-legacy-silver/10 flex items-center justify-center text-legacy-silver">
                          <UserIcon size={24} />
                        </div>
                        <div>
                          <h4 className="font-bold text-white">{contact.name}</h4>
                          <p className="text-xs text-slate-400">{contact.email}</p>
                          {contact.access_code && (
                            <div className="mt-1 flex items-center space-x-1">
                              <span className="text-[10px] text-slate-500 uppercase font-mono">Access Code:</span>
                              <span className="text-[10px] text-emerald-400 font-mono font-bold">{contact.access_code}</span>
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="mt-4 flex justify-between items-center">
                        <Badge variant={contact.status === 'verified' ? 'success' : 'success'}>
                          {contact.status === 'active' ? 'ACTIVE' : 'VERIFIED'}
                        </Badge>
                        <span className="text-[10px] text-slate-500 uppercase font-mono">{contact.relationship}</span>
                      </div>
                      <button 
                        onClick={() => deleteContact(contact.id)}
                        className="absolute top-4 right-4 text-slate-600 hover:text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Trash2 size={16} />
                      </button>
                    </Card>
                  ))}
                  {contacts.length === 0 && (
                    <div className="md:col-span-3 py-20 text-center space-y-4">
                      <p className="text-slate-400">No continuity partners added yet.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'will' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <div className="flex items-center space-x-4">
                    <h3 className="text-xl font-bold text-white">Life Continuity Plan</h3>
                    <div className="flex items-center space-x-2 bg-white/5 px-3 py-1.5 rounded-lg">
                      <Globe size={14} className="text-legacy-silver" />
                      <select 
                        value={country}
                        onChange={(e) => setCountry(e.target.value)}
                        className="bg-transparent text-xs text-white focus:outline-none"
                      >
                        <option value="United States">United States</option>
                        <option value="United Kingdom">United Kingdom</option>
                        <option value="India">India</option>
                        <option value="Canada">Canada</option>
                        <option value="Australia">Australia</option>
                      </select>
                    </div>
                  </div>
                  <button 
                    onClick={handleGenerateWill}
                    disabled={isGeneratingWill}
                    className="flex items-center space-x-2 px-6 py-2.5 rounded-full silver-gradient text-legacy-blue font-bold shadow-lg shadow-legacy-silver/20 hover:scale-105 transition-transform disabled:opacity-50"
                  >
                    {isGeneratingWill ? <div className="w-4 h-4 border-2 border-legacy-blue border-t-transparent rounded-full animate-spin"></div> : <Zap size={18} />}
                    <span>{generatedWill ? 'Regenerate Plan' : 'Generate Continuity Plan'}</span>
                  </button>
                </div>

                {generatedWill ? (
                  <Card className="prose prose-invert max-w-none">
                    <div className="flex items-center space-x-2 mb-6 p-3 rounded-xl bg-amber-500/5 border border-amber-500/20 text-amber-400 text-[10px] font-bold uppercase tracking-widest">
                      <AlertTriangle size={14} />
                      <span>AI Draft - Legally Reviewed Copy Recommended</span>
                    </div>
                    <div className="whitespace-pre-wrap text-slate-300 font-serif leading-relaxed">
                      {generatedWill}
                    </div>
                    <div className="mt-8 pt-8 border-t border-white/10 flex justify-between items-center">
                      <div className="flex items-center space-x-4">
                        <div className="flex items-center space-x-1 text-[10px] text-slate-500 uppercase tracking-widest">
                          <CheckSquare size={12} />
                          <span>Executor Defined</span>
                        </div>
                        <div className="flex items-center space-x-1 text-[10px] text-slate-500 uppercase tracking-widest">
                          <CheckSquare size={12} />
                          <span>Asset Clauses Included</span>
                        </div>
                      </div>
                      <button className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-white/5 text-slate-400 hover:text-white transition-colors">
                        <Download size={18} />
                        <span>Export as PDF</span>
                      </button>
                    </div>
                  </Card>
                ) : (
                  <div className="py-20 text-center space-y-6">
                    <div className="w-20 h-20 bg-white/5 rounded-full flex items-center justify-center mx-auto text-slate-600">
                      <FileText size={40} />
                    </div>
                    <div className="max-w-md mx-auto">
                      <h4 className="text-lg font-bold text-white mb-2">No Plan Generated</h4>
                      <p className="text-slate-400 text-sm">Use our AI engine to draft a comprehensive digital continuity plan adapted to your region's laws.</p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'messages' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-xl font-bold text-white">Emotional Continuity</h3>
                  <button 
                    onClick={() => {
                      setEditingMessage(null);
                      setMsgContent('');
                      setMsgRecipient('');
                      setMsgCategory('Celebration');
                      setMsgEvent('');
                      setShowAddMessage(true);
                    }}
                    className="flex items-center space-x-2 px-4 py-2 rounded-xl silver-gradient text-legacy-blue font-bold"
                  >
                    <Plus size={18} />
                    <span>Schedule Message</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {messages.map((msg) => (
                    <Card key={msg.id} className="space-y-4 group relative">
                      <div className="flex justify-between items-start">
                        <div className="p-3 rounded-xl bg-legacy-silver/10 text-legacy-silver">
                          {msg.type === 'Text' ? <FileText size={20} /> : <Zap size={20} />}
                        </div>
                        <div className="flex space-x-2">
                          <Badge variant="success">{msg.status}</Badge>
                        </div>
                      </div>
                      <div>
                        <h4 className="font-bold text-white">{msg.category}</h4>
                        <p className="text-xs text-slate-500">Release: {msg.release_event}</p>
                      </div>
                      <p className="text-sm text-slate-400 line-clamp-3 italic">"{msg.content}"</p>
                      <div className="pt-4 border-t border-white/5 flex justify-between items-center">
                        <span className="text-[10px] text-slate-500 font-mono">TO: {contacts.find(c => c.id === msg.recipient_id)?.name}</span>
                        <div className="flex space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button 
                            onClick={() => {
                              setEditingMessage(msg);
                              setMsgContent(msg.content);
                              setMsgRecipient(msg.recipient_id);
                              setMsgCategory(msg.category);
                              setMsgEvent(msg.release_event);
                              setShowAddMessage(true);
                            }}
                            className="p-1 text-slate-400 hover:text-white"
                          >
                            <History size={14} />
                          </button>
                          <button 
                            onClick={() => deleteMessage(msg.id)}
                            className="p-1 text-slate-400 hover:text-rose-400"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </div>
                    </Card>
                  ))}
                  {messages.length === 0 && (
                    <div className="md:col-span-3 py-20 text-center border border-dashed border-white/10 rounded-3xl">
                      <Heart size={48} className="mx-auto text-slate-700 mb-4" />
                      <p className="text-slate-400">No milestone messages scheduled yet.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'confidential' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="text-xl font-bold text-white">Confidential Credential Sharing</h3>
                  <button 
                    onClick={() => setShowConfidentialModal(true)}
                    className="flex items-center space-x-2 px-4 py-2 rounded-xl silver-gradient text-legacy-blue font-bold"
                  >
                    <Plus size={18} />
                    <span>Share New Credential</span>
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {confidentialLinks.map((link) => (
                    <Card key={link.id} className="space-y-4 relative group">
                      <div className="flex justify-between items-start">
                        <div className="p-3 rounded-xl bg-legacy-silver/10 text-legacy-silver">
                          <Lock size={20} />
                        </div>
                        <Badge variant="warning">Encrypted</Badge>
                      </div>
                      <div>
                        <h4 className="font-bold text-white">{link.title}</h4>
                        <p className="text-xs text-slate-500">For: {contacts.find(c => c.id === link.beneficiary_id)?.name}</p>
                      </div>
                      <div className="bg-black/20 p-3 rounded-xl space-y-2 font-mono text-[10px]">
                        <div className="flex justify-between">
                          <span className="text-slate-500">USER:</span>
                          <span className="text-white">{link.username}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-slate-500">PASS:</span>
                          <span className="text-white">••••••••</span>
                        </div>
                      </div>
                      {link.notes && <p className="text-xs text-slate-400 italic">"{link.notes}"</p>}
                      <div className="pt-4 border-t border-white/5 flex justify-between items-center">
                        <span className="text-[10px] text-slate-500 uppercase tracking-widest">Auto-Generated</span>
                        <button 
                          onClick={() => deleteConfidentialLink(link.id)}
                          className="text-slate-500 hover:text-rose-400 opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </Card>
                  ))}
                  {confidentialLinks.length === 0 && (
                    <div className="md:col-span-3 py-20 text-center border border-dashed border-white/10 rounded-3xl">
                      <Database size={48} className="mx-auto text-slate-700 mb-4" />
                      <p className="text-slate-400">No confidential credentials shared yet.</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === 'engine' && (
              <div className="space-y-6 max-w-4xl mx-auto">
                <div className="bg-[#151619] rounded-3xl p-8 border border-white/5 shadow-2xl relative overflow-hidden">
                  {/* Hardware aesthetic elements */}
                  <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-legacy-silver/20 to-transparent"></div>
                  <div className="absolute top-4 right-8 flex space-x-2">
                    <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]"></div>
                    <div className="w-2 h-2 rounded-full bg-slate-800"></div>
                    <div className="w-2 h-2 rounded-full bg-slate-800"></div>
                  </div>

                  <div className="space-y-8 relative z-10">
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2 text-legacy-silver mb-1">
                        <Cpu size={16} />
                        <span className="text-[10px] uppercase tracking-[0.3em] font-mono">System Configuration</span>
                      </div>
                      <h3 className="text-2xl font-bold text-white">Continuity Assurance Engine™</h3>
                      <p className="text-sm text-slate-400 max-w-2xl">Progressive legacy activation protocol. Each stage is designed to be reassuring, reversible, and human-centric.</p>
                    </div>

                    <div className="space-y-6">
                      {[
                        { stage: 'Gentle Activity Reminder', key: 'reminderDays', icon: Activity, color: 'text-emerald-400', desc: 'System-wide reassurance check via encrypted notification.' },
                        { stage: 'Wellness Confirmation Prompt', key: 'wellnessDays', icon: Heart, color: 'text-amber-400', desc: 'Secure biometric confirmation request to verify well-being.' },
                        { stage: 'Trusted Circle Awareness', key: 'circleDays', icon: Users, color: 'text-legacy-silver', desc: 'Encrypted status update shared with your primary continuity partners.' },
                        { stage: 'Legacy Readiness Stage', key: 'activationDays', icon: Award, color: 'text-legacy-silver', desc: 'Final protocol: Decryption keys released to designated beneficiaries.' }
                      ].map((step, i) => (
                        <div key={i} className="group bg-white/[0.02] border border-white/5 rounded-2xl p-6 transition-all hover:bg-white/[0.04] hover:border-white/10">
                          <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                            <div className="flex items-start space-x-4">
                              <div className={`w-12 h-12 rounded-xl bg-slate-900 flex items-center justify-center ${step.color} border border-white/5 shadow-inner`}>
                                <step.icon size={24} />
                              </div>
                              <div>
                                <h4 className="font-bold text-white text-lg">{step.stage}</h4>
                                <p className="text-xs text-slate-500 mt-1">{step.desc}</p>
                              </div>
                            </div>
                            
                            <div className="flex items-center space-x-4 bg-black/40 rounded-xl p-2 border border-white/5">
                              <div className="px-3 py-1">
                                <span className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Threshold</span>
                                <div className="flex items-center space-x-2">
                                  <input 
                                    type="number" 
                                    value={(escalationConfig as any)[step.key]}
                                    onChange={(e) => setEscalationConfig({ ...escalationConfig, [step.key]: parseInt(e.target.value) })}
                                    className="w-12 bg-transparent text-white font-mono text-lg focus:outline-none"
                                  />
                                  <span className="text-[10px] text-slate-600 font-mono">DAYS</span>
                                </div>
                              </div>
                              <div className="w-px h-8 bg-white/5"></div>
                              <div className="px-3 py-1">
                                <span className="text-[10px] text-slate-500 uppercase font-mono block mb-1">Status</span>
                                <span className="text-[10px] text-emerald-500 font-mono">STANDBY</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="pt-6 flex justify-between items-center">
                      <div className="flex items-center space-x-2 text-[10px] text-slate-500 font-mono">
                        <Shield size={12} />
                        <span>PROTOCOL VERSION 4.2.0 // ENCRYPTED SESSION</span>
                      </div>
                      <button 
                        onClick={async () => {
                          const res = await fetch('/api/user/settings', {
                            method: 'PATCH',
                            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                            body: JSON.stringify({ escalation_config: escalationConfig })
                          });
                          if (res.ok) alert("Continuity Engine settings updated successfully.");
                        }}
                        className="px-8 py-4 rounded-xl silver-gradient text-legacy-blue font-bold shadow-xl shadow-legacy-silver/10 hover:scale-105 transition-transform"
                      >
                        Commit Configuration
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'simulation' && (
              <div className="space-y-8 max-w-5xl mx-auto">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <Card className="md:col-span-2 p-8">
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-8">
                      <div>
                        <h3 className="text-xl font-bold text-white">Legacy Release Simulation</h3>
                        <p className="text-sm text-slate-400 mt-1">Preview exactly what your loved ones will see when your legacy is released.</p>
                      </div>
                      <div className="flex items-center space-x-3 w-full md:w-auto">
                        <button 
                          onClick={() => simulateEscalation('Activation')}
                          className="flex items-center space-x-2 px-4 py-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20 transition-all text-xs font-bold"
                        >
                          <Zap size={14} />
                          <span>Trigger Legacy Release</span>
                        </button>
                        <span className="text-xs text-slate-500 uppercase font-bold">Select Beneficiary:</span>
                        <select 
                          value={simulationBeneficiary || ''}
                          onChange={e => setSimulationBeneficiary(e.target.value)}
                          className="flex-1 md:flex-none bg-white/5 border border-white/10 rounded-xl px-4 py-2 text-sm text-white focus:outline-none focus:border-legacy-silver/50"
                        >
                          <option value="">Choose a partner...</option>
                          {contacts.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                        </select>
                      </div>
                    </div>

                    {simulationBeneficiary ? (
                      <div className="space-y-8">
                        <div className="p-6 rounded-2xl bg-emerald-500/5 border border-emerald-500/10 flex items-center space-x-4">
                          <div className="w-12 h-12 rounded-full bg-emerald-500/20 flex items-center justify-center text-emerald-400">
                            <CheckCircle2 size={24} />
                          </div>
                          <div>
                            <h4 className="font-bold text-white">Simulation Active: {contacts.find(c => c.id === simulationBeneficiary)?.name}'s View</h4>
                            <p className="text-xs text-slate-400">This is a preview of the secure portal they will access.</p>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                          <div className="space-y-6">
                            <h5 className="text-sm font-bold text-legacy-silver uppercase tracking-widest flex items-center space-x-2">
                              <MessageSquare size={16} />
                              <span>Legacy Messages</span>
                            </h5>
                            <div className="space-y-4">
                              {messages.filter(m => m.recipient_id === simulationBeneficiary).map(msg => (
                                <div key={msg.id} className="p-6 rounded-2xl bg-white/5 border border-white/5 space-y-4">
                                  <div className="flex justify-between items-center">
                                    <Badge variant="success">{msg.category}</Badge>
                                    <span className="text-[10px] text-slate-500 font-mono">{msg.release_event}</span>
                                  </div>
                                  <p className="text-slate-300 font-serif italic leading-relaxed">"{msg.content}"</p>
                                </div>
                              ))}
                              {messages.filter(m => m.recipient_id === simulationBeneficiary).length === 0 && (
                                <p className="text-xs text-slate-500 italic">No messages scheduled for this beneficiary.</p>
                              )}
                            </div>
                          </div>

                          <div className="space-y-6">
                            <h5 className="text-sm font-bold text-legacy-silver uppercase tracking-widest flex items-center space-x-2">
                              <Database size={16} />
                              <span>Assigned Assets</span>
                            </h5>
                            <div className="space-y-4">
                              {documents.filter(d => d.beneficiary_id === simulationBeneficiary).map(doc => (
                                <div key={doc.id} className="p-4 rounded-xl bg-white/5 border border-white/5 flex items-center justify-between">
                                  <div className="flex items-center space-x-3">
                                    <div className="p-2 rounded-lg bg-legacy-silver/10 text-legacy-silver">
                                      <File size={16} />
                                    </div>
                                    <div>
                                      <h6 className="text-sm font-bold text-white">{doc.title}</h6>
                                      <p className="text-[10px] text-slate-500 uppercase">{doc.file_type}</p>
                                    </div>
                                  </div>
                                  <button 
                                    onClick={() => downloadDocument(doc)}
                                    className="p-2 rounded-lg bg-white/5 text-slate-400 hover:text-white transition-colors"
                                  >
                                    <Download size={14} />
                                  </button>
                                </div>
                              ))}
                              {documents.filter(d => d.beneficiary_id === simulationBeneficiary).length === 0 && (
                                <p className="text-xs text-slate-500 italic">No documents assigned to this beneficiary.</p>
                              )}
                            </div>
                          </div>
                          <div className="space-y-6">
                            <h5 className="text-sm font-bold text-legacy-silver uppercase tracking-widest flex items-center space-x-2">
                              <Lock size={16} />
                              <span>Confidential Access</span>
                            </h5>
                            <div className="space-y-4">
                              {confidentialLinks.filter(l => l.beneficiary_id === simulationBeneficiary).map(link => (
                                <div key={link.id} className="p-6 rounded-2xl bg-white/5 border border-white/5 space-y-4">
                                  <h6 className="text-sm font-bold text-white">{link.title}</h6>
                                  <div className="bg-black/40 p-4 rounded-xl space-y-3 font-mono text-xs">
                                    <div className="flex justify-between items-center">
                                      <span className="text-slate-500">USERNAME:</span>
                                      <span className="text-emerald-400">{link.username}</span>
                                    </div>
                                    <div className="flex justify-between items-center">
                                      <span className="text-slate-500">PASSWORD:</span>
                                      <span className="text-emerald-400">{link.password}</span>
                                    </div>
                                  </div>
                                  <p className="text-[10px] text-slate-500 italic">This access was auto-generated for your secure transition.</p>
                                </div>
                              ))}
                              {confidentialLinks.filter(l => l.beneficiary_id === simulationBeneficiary).length === 0 && (
                                <p className="text-xs text-slate-500 italic">No confidential access shared with this beneficiary.</p>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="py-20 text-center space-y-4 border border-dashed border-white/10 rounded-3xl">
                        <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center mx-auto text-slate-700">
                          <Zap size={32} />
                        </div>
                        <p className="text-slate-500">Select a beneficiary to simulate their legacy portal experience.</p>
                      </div>
                    )}
                  </Card>
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </main>

      {/* Modals */}
      <AnimatePresence>
        {showAddSection && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowAddSection(false)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-sm glass rounded-3xl p-6 space-y-6"
            >
              <h3 className="text-xl font-bold text-white">Create New Section</h3>
              <input 
                type="text" 
                value={newSectionName}
                onChange={e => setNewSectionName(e.target.value)}
                placeholder="Section Name (e.g. Legal)"
                className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                autoFocus
              />
              <div className="flex space-x-3">
                <button onClick={() => setShowAddSection(false)} className="flex-1 py-3 rounded-xl bg-white/5 text-slate-400 font-bold">Cancel</button>
                <button onClick={addSection} className="flex-1 py-3 rounded-xl silver-gradient text-legacy-blue font-bold">Create</button>
              </div>
            </motion.div>
          </div>
        )}

        {showAddContact && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowAddContact(false)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-sm glass rounded-3xl p-6 space-y-6"
            >
              <h3 className="text-xl font-bold text-white">Add Trusted Contact</h3>
              <div className="space-y-4">
                <input 
                  type="text" 
                  value={contactName}
                  onChange={e => setContactName(e.target.value)}
                  placeholder="Full Name"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                />
                <input 
                  type="email" 
                  value={contactEmail}
                  onChange={e => setContactEmail(e.target.value)}
                  placeholder="Email Address"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                />
                <input 
                  type="text" 
                  value={contactRelationship}
                  onChange={e => setContactRelationship(e.target.value)}
                  placeholder="Relationship (e.g. Spouse)"
                  className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                />
              </div>
              <div className="flex space-x-3">
                <button onClick={() => setShowAddContact(false)} className="flex-1 py-3 rounded-xl bg-white/5 text-slate-400 font-bold">Cancel</button>
                <button onClick={addContact} className="flex-1 py-3 rounded-xl silver-gradient text-legacy-blue font-bold">Add</button>
              </div>
            </motion.div>
          </div>
        )}

        {showUpload && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => { setShowUpload(false); stopCamera(); setIsVerified(false); }}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-md glass rounded-3xl p-6 space-y-6 max-h-[90vh] overflow-y-auto"
            >
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-bold text-white">Secure Upload</h3>
                <button onClick={() => { setShowUpload(false); stopCamera(); setIsVerified(false); }} className="text-slate-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>

              {!isVerified ? (
                <div className="space-y-6">
                  <div className="text-center space-y-2">
                    <div className="w-12 h-12 bg-legacy-silver/10 rounded-full flex items-center justify-center mx-auto text-legacy-silver">
                      <Shield size={24} />
                    </div>
                    <h4 className="font-bold text-white">Biometric Verification Required</h4>
                    <p className="text-xs text-slate-400">Please verify your identity using face recognition before uploading sensitive documents.</p>
                  </div>

                  <div className="relative aspect-video bg-slate-900 rounded-2xl overflow-hidden border border-white/10 shadow-inner">
                    {!cameraStream ? (
                      <div className="absolute inset-0 flex flex-col items-center justify-center space-y-4">
                        <div className="w-12 h-12 rounded-full bg-white/5 animate-pulse flex items-center justify-center">
                          <UserIcon size={24} className="text-slate-700" />
                        </div>
                        <p className="text-[10px] text-slate-500 uppercase tracking-widest">Waking Sensors...</p>
                      </div>
                    ) : (
                      <>
                        <video 
                          ref={videoRef} 
                          autoPlay 
                          playsInline 
                          muted 
                          className="w-full h-full object-cover scale-x-[-1]"
                        />
                        <div className="absolute inset-0 pointer-events-none">
                          <motion.div 
                            initial={{ top: '0%' }}
                            animate={{ top: '100%' }}
                            transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                            className="absolute left-0 right-0 h-0.5 bg-legacy-silver/30 shadow-[0_0_10px_rgba(192,192,192,0.5)] z-10"
                          />
                        </div>
                      </>
                    )}
                    {isVerifying && (
                      <div className="absolute inset-0 bg-legacy-blue/60 backdrop-blur-sm flex flex-col items-center justify-center space-y-4 z-20">
                        <div className="w-12 h-12 border-4 border-legacy-silver border-t-transparent rounded-full animate-spin"></div>
                        <p className="text-legacy-silver font-mono text-xs animate-pulse tracking-widest">SCANNING RETINA...</p>
                      </div>
                    )}
                  </div>

                  <button 
                    onClick={handleVerify}
                    disabled={!cameraStream || isVerifying}
                    className="w-full py-4 rounded-xl silver-gradient text-legacy-blue font-bold shadow-lg shadow-legacy-silver/20 disabled:opacity-50 transition-all flex items-center justify-center space-x-2"
                  >
                    <Lock size={18} />
                    <span>Verify Identity</span>
                  </button>
                </div>
              ) : (
                <form onSubmit={handleUpload} className="space-y-4">
                  <div className="flex items-center space-x-2 text-emerald-400 bg-emerald-500/10 p-3 rounded-xl border border-emerald-500/20 mb-4">
                    <CheckCircle2 size={18} />
                    <span className="text-xs font-bold uppercase tracking-wider">Identity Verified</span>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Title</label>
                    <input 
                      type="text" 
                      value={uploadTitle}
                      onChange={e => setUploadTitle(e.target.value)}
                      placeholder="Document Title"
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Priority</label>
                    <select 
                      value={uploadPriority}
                      onChange={e => setUploadPriority(e.target.value as any)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                    >
                      <option value="High">High</option>
                      <option value="Medium">Medium</option>
                      <option value="Low">Low</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Notes</label>
                    <textarea 
                      value={uploadNotes}
                      onChange={e => setUploadNotes(e.target.value)}
                      placeholder="Add any relevant notes or instructions..."
                      rows={3}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50 resize-none"
                    />
                  </div>
                  
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Assign Beneficiary</label>
                    <select 
                      value={uploadBeneficiary}
                      onChange={e => setUploadBeneficiary(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                    >
                      <option value="">No Assignment (Vault Only)</option>
                      {contacts.map(c => <option key={c.id} value={c.id}>{c.name} ({c.relationship})</option>)}
                    </select>
                  </div>

                  <div 
                    className={`border-2 border-dashed rounded-2xl p-8 text-center transition-colors ${uploadFile ? 'border-emerald-500/50 bg-emerald-500/5' : 'border-white/10 hover:border-legacy-silver/50'}`}
                    onDragOver={e => e.preventDefault()}
                    onDrop={e => {
                      e.preventDefault();
                      if (e.dataTransfer.files[0]) setUploadFile(e.dataTransfer.files[0]);
                    }}
                  >
                    <input 
                      type="file" 
                      id="file-upload" 
                      className="hidden" 
                      onChange={e => e.target.files && setUploadFile(e.target.files[0])}
                    />
                    <label htmlFor="file-upload" className="cursor-pointer space-y-2 block">
                      <Upload className={`mx-auto ${uploadFile ? 'text-emerald-400' : 'text-slate-500'}`} size={32} />
                      <p className="text-sm text-slate-400">
                        {uploadFile ? uploadFile.name : 'Drag & drop or click to upload'}
                      </p>
                    </label>
                  </div>

                  <div className="flex space-x-3 pt-2">
                    <button type="button" onClick={() => { setShowUpload(false); setIsVerified(false); }} className="flex-1 py-3 rounded-xl bg-white/5 text-slate-400 font-bold" disabled={isUploading}>Cancel</button>
                    <button type="submit" disabled={!uploadFile || isUploading} className="flex-1 py-3 rounded-xl silver-gradient text-legacy-blue font-bold disabled:opacity-50 flex items-center justify-center space-x-2">
                      {isUploading ? (
                        <>
                          <div className="w-4 h-4 border-2 border-legacy-blue border-t-transparent rounded-full animate-spin"></div>
                          <span>{uploadProgress}%</span>
                        </>
                      ) : (
                        <span>Upload</span>
                      )}
                    </button>
                  </div>

                  {isUploading && (
                    <div className="space-y-2">
                      <div className="w-full bg-white/5 h-1.5 rounded-full overflow-hidden">
                        <motion.div 
                          initial={{ width: 0 }}
                          animate={{ width: `${uploadProgress}%` }}
                          className="bg-legacy-silver h-full"
                        />
                      </div>
                      <p className="text-[10px] text-center text-slate-500 uppercase tracking-widest">Encrypting & Storing...</p>
                    </div>
                  )}
                </form>
              )}
            </motion.div>
          </div>
        )}

        {previewDoc && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={closePreview}
              className="absolute inset-0 bg-black/80 backdrop-blur-md"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-5xl glass rounded-3xl overflow-hidden flex flex-col max-h-[90vh]"
            >
              <div className="p-6 border-b border-white/10 flex justify-between items-center bg-legacy-blue/50">
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-lg bg-legacy-silver/10 text-legacy-silver">
                    <File size={20} />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">{previewDoc.title}</h3>
                    <p className="text-xs text-slate-500 uppercase tracking-widest">{previewDoc.file_type}</p>
                  </div>
                </div>
                <button onClick={closePreview} className="text-slate-400 hover:text-white p-2">
                  <X size={24} />
                </button>
              </div>

              <div className="flex flex-col lg:flex-row flex-1 overflow-hidden">
                <div className="flex-1 bg-slate-900/50 relative min-h-[400px] flex items-center justify-center overflow-auto">
                  {isPreviewLoading ? (
                    <div className="flex flex-col items-center space-y-4">
                      <div className="w-12 h-12 border-4 border-legacy-silver border-t-transparent rounded-full animate-spin"></div>
                      <p className="text-legacy-silver font-mono text-xs animate-pulse tracking-widest">DECRYPTING SECURE DATA...</p>
                    </div>
                  ) : previewUrl ? (
                    previewDoc.file_type?.startsWith('image/') ? (
                      <img src={previewUrl} alt={previewDoc.title} className="max-w-full max-h-full object-contain" />
                    ) : previewDoc.file_type === 'application/pdf' ? (
                      <iframe src={previewUrl} className="w-full h-full border-none" title="PDF Preview" />
                    ) : (
                      <div className="text-center space-y-4 p-8">
                        <div className="w-16 h-16 bg-white/5 rounded-full flex items-center justify-center mx-auto text-slate-500">
                          <FileText size={32} />
                        </div>
                        <p className="text-slate-400">Preview not available for this file type.</p>
                        <a 
                          href={previewUrl} 
                          download={previewDoc.title}
                          className="inline-flex items-center space-x-2 px-6 py-2.5 rounded-full silver-gradient text-legacy-blue font-bold"
                        >
                          <Download size={18} />
                          <span>Download to View</span>
                        </a>
                      </div>
                    )
                  ) : (
                    <p className="text-rose-400">Failed to load preview.</p>
                  )}
                </div>

                <div className="w-full lg:w-80 border-t lg:border-t-0 lg:border-l border-white/10 p-6 flex flex-col space-y-6 bg-legacy-blue/20 overflow-y-auto">
                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Continuity Assets</h4>
                    <div className="space-y-3">
                      <div className="flex justify-between items-center">
                        <span className="text-xs text-slate-400">Priority</span>
                        <Badge variant={PriorityColors[previewDoc.priority]}>{previewDoc.priority}</Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-xs text-slate-400">Versions</span>
                        <span className="text-xs text-white flex items-center space-x-1">
                          <History size={10} />
                          <span>{previewDoc.version_count || 1} Revisions</span>
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Integrity Layer</h4>
                    {previewDoc.integrity_hash ? (
                      <div className="p-3 rounded-xl bg-emerald-500/5 border border-emerald-500/20 space-y-2">
                        <div className="flex items-center space-x-2 text-emerald-400">
                          <CheckSquare size={14} />
                          <span className="text-[10px] font-bold uppercase">Blockchain Verified</span>
                        </div>
                        <p className="text-[8px] font-mono text-slate-500 break-all">{previewDoc.integrity_hash}</p>
                      </div>
                    ) : (
                      <button 
                        onClick={() => handleBlockchainVerify(previewDoc.id)}
                        className="w-full py-2 rounded-xl bg-white/5 border border-white/10 text-[10px] font-bold uppercase tracking-widest hover:bg-white/10 transition-colors"
                      >
                        Generate Integrity Proof
                      </button>
                    )}
                  </div>

                  <div className="space-y-4">
                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Legacy Assignment</h4>
                    <div className="space-y-2">
                      <select 
                        value={previewDoc.beneficiary_id || ''}
                        onChange={(e) => updateBeneficiary(previewDoc.id, e.target.value)}
                        className="w-full bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-xs text-white focus:outline-none focus:border-legacy-silver/50"
                      >
                        <option value="">Unassigned</option>
                        {contacts.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                      </select>
                      <p className="text-[10px] text-slate-500 italic">
                        {previewDoc.beneficiary_id 
                          ? `Assigned to ${contacts.find(c => c.id === previewDoc.beneficiary_id)?.name}. This asset will be released to them upon legacy activation.` 
                          : 'This asset is currently private and will not be released to anyone.'}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-4 flex-1 flex flex-col">
                    <h4 className="text-xs font-bold text-slate-500 uppercase tracking-widest">Continuity Notes</h4>
                    <textarea 
                      value={previewDoc.notes || ''}
                      onChange={(e) => updateNotes(previewDoc.id, e.target.value)}
                      placeholder="Add guidance for your legacy..."
                      className="flex-1 w-full bg-white/5 border border-white/10 rounded-xl p-3 text-sm text-slate-300 focus:outline-none focus:border-legacy-silver/50 resize-none"
                    />
                  </div>
                </div>
              </div>
            </motion.div>
          </div>
        )}
        {showAddMessage && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowAddMessage(false)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-lg glass rounded-3xl p-6 space-y-6"
            >
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-bold text-white">{editingMessage ? 'Edit Milestone Message' : 'Schedule Milestone Message'}</h3>
                <button onClick={() => { setShowAddMessage(false); setEditingMessage(null); }} className="text-slate-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Recipient</label>
                    <select 
                      value={msgRecipient}
                      onChange={e => setMsgRecipient(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                    >
                      <option value="">Select Contact</option>
                      {contacts.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Category</label>
                    <select 
                      value={msgCategory}
                      onChange={e => setMsgCategory(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                    >
                      <option value="Celebration">Celebration</option>
                      <option value="Guidance">Guidance</option>
                      <option value="Milestone Blessing">Milestone Blessing</option>
                      <option value="Personal Reflection">Personal Reflection</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-500 uppercase ml-1">Release Event</label>
                  <input 
                    type="text" 
                    value={msgEvent}
                    onChange={e => setMsgEvent(e.target.value)}
                    placeholder="e.g., 21st Birthday, Wedding Day"
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                  />
                </div>

                <div className="space-y-1">
                  <div className="flex justify-between items-center">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Message Content</label>
                    <button 
                      onClick={handleDraftMessage}
                      disabled={isDraftingMsg || !msgContent}
                      className="text-[10px] uppercase tracking-widest text-legacy-silver flex items-center space-x-1"
                    >
                      <Cpu size={10} />
                      <span>{isDraftingMsg ? 'Drafting...' : 'AI Assist'}</span>
                    </button>
                  </div>
                  <textarea 
                    value={msgContent}
                    onChange={e => setMsgContent(e.target.value)}
                    placeholder="Write your heartfelt message here..."
                    rows={5}
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50 resize-none"
                  />
                </div>

                <button 
                  onClick={saveMessage}
                  disabled={!msgRecipient || !msgContent}
                  className="w-full py-4 rounded-xl silver-gradient text-legacy-blue font-bold shadow-lg shadow-legacy-silver/20 disabled:opacity-50"
                >
                  {editingMessage ? 'Update Emotional Continuity' : 'Schedule Emotional Continuity'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
        {showJuryBrief && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowJuryBrief(false)}
              className="absolute inset-0 bg-black/80 backdrop-blur-md"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-2xl glass rounded-3xl p-8 space-y-8 max-h-[90vh] overflow-y-auto"
            >
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 silver-gradient rounded-xl flex items-center justify-center">
                    <Shield className="text-legacy-blue" size={24} />
                  </div>
                  <h3 className="text-2xl font-serif font-bold text-white">Project: Legacy-Lock</h3>
                </div>
                <button onClick={() => setShowJuryBrief(false)} className="text-slate-400 hover:text-white">
                  <X size={24} />
                </button>
              </div>

              <div className="space-y-6 text-slate-300">
                <section className="space-y-2">
                  <h4 className="text-legacy-silver font-bold uppercase tracking-widest text-xs">The Mission</h4>
                  <p className="text-sm leading-relaxed">Legacy-Lock is a premium digital estate platform designed to solve the "Digital Ghost" problem. It ensures that your digital assets, memories, and legal intentions are gracefully transitioned to loved ones if you are no longer able to manage them.</p>
                </section>

                <section className="space-y-4">
                  <h4 className="text-legacy-silver font-bold uppercase tracking-widest text-xs">Unique Innovations</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-2xl bg-white/5 border border-white/5">
                      <h5 className="text-white font-bold text-sm mb-1">Life Continuity Mode™</h5>
                      <p className="text-[11px] text-slate-500">A non-morbid approach to legacy. The system monitors "Continuity" rather than "Death", using AI to detect pattern shifts.</p>
                    </div>
                    <div className="p-4 rounded-2xl bg-white/5 border border-white/5">
                      <h5 className="text-white font-bold text-sm mb-1">Biometric Vault</h5>
                      <p className="text-[11px] text-slate-500">AES-256 encryption combined with mandatory face-verification for all sensitive asset management.</p>
                    </div>
                    <div className="p-4 rounded-2xl bg-white/5 border border-white/5">
                      <h5 className="text-white font-bold text-sm mb-1">Blockchain Proof</h5>
                      <p className="text-[11px] text-slate-500">Generates immutable "Proof-of-Existence" for documents, ensuring integrity during the transition.</p>
                    </div>
                    <div className="p-4 rounded-2xl bg-white/5 border border-white/5">
                      <h5 className="text-white font-bold text-sm mb-1">Emotional Continuity</h5>
                      <p className="text-[11px] text-slate-500">AI-assisted milestone messages that release on specific future events (birthdays, weddings).</p>
                    </div>
                  </div>
                </section>

                <section className="space-y-2">
                  <h4 className="text-legacy-silver font-bold uppercase tracking-widest text-xs">Jury Note</h4>
                  <p className="text-sm leading-relaxed italic">"The core value is the Graceful Transition. By assigning specific assets to specific partners in the Trust Network, the user creates a personalized legacy roadmap that activates automatically yet reversibly."</p>
                </section>
              </div>

              <button 
                onClick={() => setShowJuryBrief(false)}
                className="w-full py-4 rounded-xl silver-gradient text-legacy-blue font-bold shadow-lg shadow-legacy-silver/20"
              >
                Explore Platform
              </button>
            </motion.div>
          </div>
        )}
        {showConfidentialModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowConfidentialModal(false)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-md glass rounded-3xl p-6 space-y-6"
            >
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-bold text-white">Share Confidential Access</h3>
                <button onClick={() => setShowConfidentialModal(false)} className="text-slate-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>

              <div className="space-y-4">
                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-500 uppercase ml-1">Title</label>
                  <input 
                    type="text" 
                    value={confTitle}
                    onChange={e => setConfTitle(e.target.value)}
                    placeholder="e.g., Primary Bank Account, Family Trust"
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-500 uppercase ml-1">Beneficiary</label>
                  <select 
                    value={confBeneficiary}
                    onChange={e => setConfBeneficiary(e.target.value)}
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50"
                  >
                    <option value="">Select Partner</option>
                    {contacts.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-500 uppercase ml-1">Additional Notes</label>
                  <textarea 
                    value={confNotes}
                    onChange={e => setConfNotes(e.target.value)}
                    placeholder="Any specific instructions for this access..."
                    rows={3}
                    className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none focus:border-legacy-silver/50 resize-none"
                  />
                </div>

                <div className="p-4 rounded-xl bg-legacy-silver/5 border border-legacy-silver/10">
                  <p className="text-[10px] text-slate-500 leading-relaxed">
                    <span className="text-legacy-silver font-bold">Note:</span> The system will automatically generate a unique, high-entropy username and password for this beneficiary. These credentials will only be released upon legacy activation.
                  </p>
                </div>

                <button 
                  onClick={generateConfidentialLink}
                  disabled={!confTitle || !confBeneficiary}
                  className="w-full py-4 rounded-xl silver-gradient text-legacy-blue font-bold shadow-lg shadow-legacy-silver/20 disabled:opacity-50"
                >
                  Generate & Share Access
                </button>
              </div>
            </motion.div>
          </div>
        )}
        {showDeathCertModal && (
          <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setShowDeathCertModal(false)}
              className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-md glass rounded-3xl p-6 space-y-6"
            >
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-bold text-white">Death Verification</h3>
                <button onClick={() => setShowDeathCertModal(false)} className="text-slate-400 hover:text-white">
                  <X size={20} />
                </button>
              </div>

              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-rose-500/5 border border-rose-500/10 text-rose-400 text-xs leading-relaxed">
                  Uploading a death certificate is a critical action. Once verified, the legacy release protocol will activate immediately.
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-bold text-slate-500 uppercase ml-1">Certificate File</label>
                  <div className="relative group">
                    <input 
                      type="file" 
                      onChange={e => setDeathCertFile(e.target.files?.[0] || null)}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                    />
                    <div className="w-full bg-white/5 border border-dashed border-white/10 rounded-xl px-4 py-8 flex flex-col items-center justify-center space-y-2 group-hover:border-legacy-silver/30 transition-all">
                      <Upload size={24} className="text-slate-500" />
                      <p className="text-xs text-slate-400">{deathCertFile ? deathCertFile.name : 'Select PDF or Image'}</p>
                    </div>
                  </div>
                </div>

                {!beneficiaryToken && (
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-500 uppercase ml-1">Reporting Beneficiary</label>
                    <select 
                      value={simulationBeneficiary || ''}
                      onChange={e => setSimulationBeneficiary(e.target.value)}
                      className="w-full bg-white/5 border border-white/10 rounded-xl px-4 py-3 text-white focus:outline-none"
                    >
                      <option value="">Select Partner</option>
                      {contacts.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                    </select>
                  </div>
                )}

                <button 
                  onClick={handleDeathCertUpload}
                  disabled={!deathCertFile || isUploadingDeathCert}
                  className="w-full py-4 rounded-xl bg-rose-500 text-white font-bold shadow-lg shadow-rose-500/20 disabled:opacity-50"
                >
                  {isUploadingDeathCert ? 'Uploading...' : 'Submit for Verification'}
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
}
