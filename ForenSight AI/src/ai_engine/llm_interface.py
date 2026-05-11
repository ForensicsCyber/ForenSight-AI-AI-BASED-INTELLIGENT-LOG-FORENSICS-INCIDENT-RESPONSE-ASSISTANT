"""
ForenSight AI - Local LLM Interface
===================================

Provides interaction layer for local Large
Language Models (LLMs) via Ollama.

Supported Model
---------------
Llama 3

Responsibilities
----------------
1. Manage Ollama communication
2. Handle prompt submission
3. Process AI responses
4. Gracefully handle LLM availability failures

Architecture Notes
------------------
• Designed for offline/local AI execution
• Compatible with packaged (.exe) deployment
• Prevents application crashes if Ollama unavailable
"""

# ---------------------------------------------------------
# OLLAMA IMPORT
# ---------------------------------------------------------

try:

    import ollama

    OLLAMA_AVAILABLE = True

except Exception:

    ollama = None

    OLLAMA_AVAILABLE = False


# ---------------------------------------------------------
# LOCAL LLM WRAPPER
# ---------------------------------------------------------

class LocalLLM:
    """
    Lightweight wrapper for local Llama 3 model.
    """

    def __init__(self, model="llama3"):
        """
        Initialize LLM configuration.

        Parameters
        ----------
        model : str
            Ollama model name
        """

        self.model = model

    # ---------------------------------------------------------
    # TEXT GENERATION
    # ---------------------------------------------------------

    def generate(self, prompt):
        """
        Generate AI response from local model.

        Parameters
        ----------
        prompt : str
            Prompt submitted to LLM

        Returns
        -------
        str
            Generated AI response
        """

        # ---------------------------------------------------------
        # Validate Ollama Availability
        # ---------------------------------------------------------

        if not OLLAMA_AVAILABLE or ollama is None:

            return (
                "AI unavailable "
                "(Ollama not installed or not accessible)"
            )

        try:

            response = ollama.chat(

                model=self.model,

                messages=[

                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert."
                        )
                    },

                    {
                        "role": "user",
                        "content": prompt
                    }

                ]

            )

            return response["message"]["content"]

        except Exception:

            return "AI generation failed"