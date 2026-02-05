"""Service for sending callbacks to GUVI evaluation endpoint."""
import requests
from typing import List, Optional
from groq import Groq
from app.models.session_state import SessionState, Message
from app.models.intelligence import GuviCallbackPayload, ExtractedIntelligence
from app.config import config
from app.utils.logger import logger


class CallbackService:
    """Handles callbacks to GUVI evaluation endpoint."""
    
    def __init__(self):
        self.callback_url = config.GUVI_CALLBACK_URL
        self.sent_callbacks = set()  # Track sent callbacks to avoid duplicates
        self._groq_client: Optional[Groq] = None
        self._init_groq_client()
    
    def _init_groq_client(self):
        """Initialize Groq client for LLM-based agent notes generation."""
        if config.GROQ_API_KEY:
            try:
                self._groq_client = Groq(api_key=config.GROQ_API_KEY)
                logger.info("CallbackService: Groq client initialized for agent notes generation")
            except Exception as e:
                logger.warning(f"CallbackService: Failed to initialize Groq: {e}. Will use fallback summary.")
                self._groq_client = None
        else:
            logger.warning("CallbackService: GROQ_API_KEY not found - will use fallback summary")
            self._groq_client = None
    
    def generate_agent_notes_summary(
        self,
        session: SessionState,
        conversation_history: List[Message],
        intelligence: ExtractedIntelligence
    ) -> str:
        """
        Generate LLM-based natural language summary explaining why the agent thought it was a scam.
        
        Uses LLM to analyze the full conversation and generate a concise explanation.
        Falls back to structured summary if LLM is unavailable.
        """
        # Try LLM first if available
        if self._groq_client:
            try:
                llm_summary = self._generate_llm_summary(
                    session,
                    conversation_history,
                    intelligence
                )
                if llm_summary:
                    return llm_summary
            except Exception as e:
                logger.warning(f"Failed to generate LLM summary, using fallback: {e}")
        
        # Fallback to structured summary
        return self._generate_fallback_summary(session, conversation_history, intelligence)
    
    def _generate_llm_summary(
        self,
        session: SessionState,
        conversation_history: List[Message],
        intelligence: ExtractedIntelligence
    ) -> Optional[str]:
        """Generate LLM-based natural language explanation of why it's a scam."""
        # Build conversation context
        conversation_text = ""
        if conversation_history:
            conversation_text = "\n".join([
                f"{'Scammer' if msg.sender == 'scammer' else 'User'}: {msg.text}"
                for msg in conversation_history
            ])
        
        # Build intelligence context
        intelligence_context = []
        if intelligence.phoneNumbers:
            intelligence_context.append(f"Phone numbers extracted: {', '.join(intelligence.phoneNumbers)}")
        if intelligence.upiIds:
            intelligence_context.append(f"UPI IDs extracted: {', '.join(intelligence.upiIds[:5])}")
        if intelligence.phishingLinks:
            intelligence_context.append(f"Phishing links: {', '.join(intelligence.phishingLinks[:3])}")
        if intelligence.bankAccounts:
            intelligence_context.append(f"Bank accounts mentioned: {len(intelligence.bankAccounts)}")
        
        intelligence_text = "\n".join(intelligence_context) if intelligence_context else "No specific intelligence extracted"
        
        # Build prompt
        prompt = f"""You are analyzing a scam conversation that was detected by an AI honeypot system.

Full conversation history:
{conversation_text}

Extracted intelligence:
{intelligence_text}

Detection details:
- Confidence score: {session.scamConfidence:.2f}
- Detection method: {session.finalDecisionReason or 'LLM-based detection'}

Your task: Write a concise, natural language explanation (2-4 sentences) explaining why this conversation was classified as a scam. Focus on:
1. The key scam indicators in the conversation
2. What the scammer was trying to achieve
3. The extracted intelligence (especially phone numbers) and why they matter
4. The overall scam pattern

Write in clear, professional language. Be specific about what made this a scam.

Explanation:"""

        try:
            response = self._groq_client.chat.completions.create(
                model=config.GROQ_MODEL,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,  # Lower temperature for more consistent, factual output
                max_tokens=300,  # Keep it concise
                top_p=0.9,
            )
            
            summary = response.choices[0].message.content.strip()
            logger.info(f"Generated LLM summary for session {session.sessionId}")
            return summary
            
        except Exception as e:
            logger.error(f"Error generating LLM summary: {e}", exc_info=True)
            return None
    
    def _generate_fallback_summary(
        self,
        session: SessionState,
        conversation_history: List[Message],
        intelligence: ExtractedIntelligence
    ) -> str:
        """Generate fallback structured summary when LLM is unavailable."""
        summary_parts = []
        
        summary_parts.append(f"Scam detected with confidence {session.scamConfidence:.2f}. ")
        
        if session.finalDecisionReason:
            summary_parts.append(f"Detection reason: {session.finalDecisionReason}. ")
        
        # Key intelligence
        if intelligence.phoneNumbers:
            summary_parts.append(f"Extracted phone numbers: {', '.join(intelligence.phoneNumbers)}. ")
        
        if intelligence.upiIds:
            summary_parts.append(f"Extracted UPI IDs: {', '.join(intelligence.upiIds[:3])}. ")
        
        if intelligence.phishingLinks:
            summary_parts.append(f"Phishing links detected: {len(intelligence.phishingLinks)}. ")
        
        # Conversation highlights
        if conversation_history:
            scammer_messages = [msg for msg in conversation_history if msg.sender == "scammer"]
            if scammer_messages:
                summary_parts.append(f"Conversation involved {len(scammer_messages)} messages from scammer, including requests for verification or sensitive information.")
        
        return "".join(summary_parts).strip()
    
    def send_callback(self, session: SessionState) -> bool:
        """
        Send intelligence callback to GUVI endpoint.
        
        Returns:
            True if successful, False otherwise
        """
        # Avoid duplicate callbacks
        if session.sessionId in self.sent_callbacks:
            return True
        
        # Generate comprehensive agent notes summary
        agent_notes_summary = self.generate_agent_notes_summary(
            session,
            session.conversationHistory,
            session.extractedIntelligence
        )
        
        # Prepare payload
        payload = GuviCallbackPayload(
            sessionId=session.sessionId,
            scamDetected=session.scamDetected,
            totalMessagesExchanged=session.totalMessagesExchanged,
            extractedIntelligence=session.extractedIntelligence,
            agentNotes=agent_notes_summary
        )
        
        # Print the request that will be sent to GUVI
        import json
        payload_dict = payload.model_dump()
        
        print("\n" + "="*80)
        print("📤 GUVI CALLBACK REQUEST")
        print("="*80)
        print(f"URL: {self.callback_url}")
        print(f"Method: POST")
        print(f"Headers: {{'Content-Type': 'application/json'}}")
        print("\nPayload:")
        print(json.dumps(payload_dict, indent=2, ensure_ascii=False))
        print("="*80 + "\n")
        
        logger.info("="*80)
        logger.info("📤 GUVI CALLBACK REQUEST")
        logger.info("="*80)
        logger.info(f"URL: {self.callback_url}")
        logger.info("Method: POST")
        logger.info("Headers: {'Content-Type': 'application/json'}")
        logger.info("Payload:\n" + json.dumps(payload_dict, indent=2, ensure_ascii=False))
        logger.info("="*80)
        
        # Send callback to GUVI endpoint
        try:
            response = requests.post(
                self.callback_url,
                json=payload_dict,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            # Print response
            print(f"Response Status: {response.status_code}")
            print(f"Response Body: {response.text[:500]}")
            print("="*80 + "\n")
            
            if response.status_code in [200, 201]:
                self.sent_callbacks.add(session.sessionId)
                session.callbackSent = True
                logger.info(f"✅ Callback sent successfully for session {session.sessionId}")
                logger.info(f"Response Status: {response.status_code}")
                logger.info(f"Response Body: {response.text[:500]}")
                return True
            else:
                logger.error(f"❌ Callback failed with status {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Error sending callback: {e}", exc_info=True)
            print(f"❌ Error sending callback: {e}")
            print("="*80 + "\n")
            return False
    
    def should_send_callback(self, session: SessionState) -> bool:
        """
        Check if callback should be sent for this session.
        
        Callback should ONLY be sent when:
        1. Conversation has ended (conversationEnded = True)
        2. Scam was detected
        3. Minimum messages exchanged
        4. We have meaningful intelligence
        5. Callback hasn't been sent yet
        """
        # Don't send if already sent
        if session.sessionId in self.sent_callbacks or session.callbackSent:
            return False
        
        # Only send when conversation has ended
        if not session.conversationEnded:
            return False
        
        if not session.scamDetected:
            return False
        
        if session.totalMessagesExchanged < config.MIN_MESSAGES_FOR_CALLBACK:
            return False
        
        # Check if we have meaningful intelligence
        intelligence = session.extractedIntelligence
        has_intelligence = (
            len(intelligence.bankAccounts) > 0 or
            len(intelligence.upiIds) > 0 or
            len(intelligence.phishingLinks) > 0 or
            len(intelligence.phoneNumbers) > 0 or
            len(intelligence.suspiciousKeywords) > 0
        )
        
        return has_intelligence


# Global callback service instance
callback_service = CallbackService()
