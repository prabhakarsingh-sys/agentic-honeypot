"""Session state models."""
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from datetime import datetime
from app.models.intelligence import ExtractedIntelligence


class Message(BaseModel):
    """Represents a single message in the conversation."""
    sender: str = Field(..., description="Message sender: 'scammer' or 'user'")
    text: str = Field(..., description="Message content")
    timestamp: str = Field(..., description="ISO-8601 timestamp")


class Metadata(BaseModel):
    """Metadata about the conversation."""
    channel: Optional[str] = Field(None, description="SMS / WhatsApp / Email / Chat")
    language: Optional[str] = Field(None, description="Language used")
    locale: Optional[str] = Field(None, description="Country or region")


class SessionState(BaseModel):
    """Internal session state management."""
    sessionId: str
    conversationHistory: List[Message] = Field(default_factory=list)
    extractedIntelligence: ExtractedIntelligence = Field(default_factory=ExtractedIntelligence)
    scamDetected: bool = False
    scamConfidence: float = 0.0
    totalMessagesExchanged: int = 0
    agentNotes: List[str] = Field(default_factory=list)
    conversationEnded: bool = Field(default=False, description="True when conversation is completed")
    callbackSent: bool = Field(default=False, description="True when callback has been sent")
    createdAt: datetime = Field(default_factory=datetime.now)
    lastUpdated: datetime = Field(default_factory=datetime.now)
    
    # Audit fields for hybrid scam detection
    scamRuleScore: Optional[float] = Field(default=None, description="Rule-based confidence score")
    scamRuleEvidence: List[str] = Field(default_factory=list, description="List of rules that matched")
    llmFallbackUsed: bool = Field(default=False, description="Whether LLM fallback was used")
    llmScamResult: Optional[Dict] = Field(default=None, description="LLM fallback result (JSON)")
    finalDecisionReason: Optional[str] = Field(default=None, description="Explanation for final scam decision")