"""
Tsukiko Configuration and Settings System
Type-safe configuration validated via Pydantic, supporting YAML loading,
environment overrides, and privacy guarantees.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field, field_validator


class AppConfig(BaseModel):
    name: str = "Tsukiko"
    version: str = "0.1.0"
    log_level: str = "INFO"
    debug: bool = False


class PrivacyConfig(BaseModel):
    local_only: bool = Field(default=True, description="Enforces strict zero-outbound-network policy")
    allow_external_telemetry: bool = Field(default=False, description="Disables all external telemetry")
    allow_cloud_fallback: bool = Field(default=False, description="Disallows fallback to cloud LLMs")

    @field_validator("local_only")
    @classmethod
    def validate_local_only(cls, v: bool) -> bool:
        if not v:
            raise ValueError("Tsukiko is strictly offline-first: privacy.local_only must be True.")
        return v

    @field_validator("allow_external_telemetry")
    @classmethod
    def validate_no_telemetry(cls, v: bool) -> bool:
        if v:
            raise ValueError("External telemetry is forbidden by Tsukiko offline privacy contract.")
        return v

    @field_validator("allow_cloud_fallback")
    @classmethod
    def validate_no_cloud(cls, v: bool) -> bool:
        if v:
            raise ValueError("Cloud fallback is forbidden by Tsukiko offline privacy contract.")
        return v


class UIConfig(BaseModel):
    theme: str = "silver-blue-moonlight"
    always_on_top: bool = True
    default_corner: str = "bottom-right"
    margin_x: int = 24
    margin_y: int = 48
    companion_size: int = 96
    fps: int = 30
    idle_animation: bool = True
    accent_color: str = "#7FB3D5"
    glow_color: str = "#D4E6F1"
    background_opacity: float = 0.92


class AIConfig(BaseModel):
    engine: str = "llama_cpp"
    model_path: Optional[str] = None
    vision_model_path: Optional[str] = None
    context_window: int = 4096
    temperature: float = 0.7
    top_p: float = 0.9
    repeat_penalty: float = 1.1
    gpu_layers: int = 0
    max_vram_mb: int = 2800  # Conservative limit for 4GB RTX 3050 Laptop
    lazy_load: bool = True
    unload_timeout_seconds: int = 300


class MemoryConfig(BaseModel):
    db_path: str = "data/memory/tsukiko_memory.sqlite"
    conversation_dir: str = "data/conversations"
    auto_summarize_threshold: int = 20
    duplicate_similarity_threshold: float = 0.85


class PerceptionConfig(BaseModel):
    screen_sharing_enabled: bool = Field(default=False, description="Screen sharing must be OFF by default")
    capture_method: str = "windows_native"
    target_fps: int = 10
    change_threshold: float = 0.05
    enable_ocr: bool = True
    enable_ui_automation: bool = True
    excluded_windows: List[str] = Field(
        default_factory=lambda: [
            "*1Password*",
            "*Bitwarden*",
            "*KeePass*",
            "*Private Browsing*",
            "*Incognito*",
        ]
    )
    save_raw_recordings: bool = False


class VoiceConfig(BaseModel):
    mic_enabled: bool = Field(default=False, description="Microphone must be OFF by default")
    speech_synthesis_enabled: bool = False
    stt_engine: str = "whisper"
    stt_model_size: str = "tiny.en"
    tts_engine: str = "piper"
    tts_voice: str = "en_US-lessac-medium"
    speed: float = 1.0
    volume: float = 0.85


class DesktopControlConfig(BaseModel):
    enabled: bool = Field(default=False, description="Desktop control must be disabled in early phases")
    require_explicit_confirmation: bool = True
    allowed_actions: List[str] = Field(default_factory=list)


class TsukikoConfig(BaseModel):
    app: AppConfig = Field(default_factory=AppConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    ui: UIConfig = Field(default_factory=UIConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    perception: PerceptionConfig = Field(default_factory=PerceptionConfig)
    voice: VoiceConfig = Field(default_factory=VoiceConfig)
    desktop_control: DesktopControlConfig = Field(default_factory=DesktopControlConfig)

    def save_yaml(self, path: str | Path) -> None:
        """Serializes configuration to YAML file."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            yaml.safe_dump(self.model_dump(), f, sort_keys=False, default_flow_style=False)


_CONFIG_INSTANCE: Optional[TsukikoConfig] = None


def find_default_config_path() -> Path:
    """Finds the default config file relative to project root."""
    # Check current directory / config
    candidate = Path("config/default_config.yaml")
    if candidate.exists():
        return candidate.resolve()
    # Check relative to module path
    module_root = Path(__file__).resolve().parent.parent.parent.parent
    candidate = module_root / "config" / "default_config.yaml"
    if candidate.exists():
        return candidate.resolve()
    return Path("config/default_config.yaml")


def _parse_env_value(val: str) -> Any:
    """Parses typed values (bool, int, float, None, str) from environment variable strings."""
    stripped = val.strip()
    lower = stripped.lower()
    if lower in ("true", "yes", "1", "on"):
        return True
    if lower in ("false", "no", "0", "off"):
        return False
    if lower in ("none", "null"):
        return None
    try:
        return int(stripped)
    except ValueError:
        pass
    try:
        return float(stripped)
    except ValueError:
        pass
    if (stripped.startswith('"') and stripped.endswith('"')) or (stripped.startswith("'") and stripped.endswith("'")):
        return stripped[1:-1]
    return stripped


def load_config(config_path: Optional[str | Path] = None, force_reload: bool = False) -> TsukikoConfig:
    """Loads configuration from YAML file and applies environment overrides."""
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is not None and not force_reload and config_path is None:
        return _CONFIG_INSTANCE

    resolved_path = Path(config_path) if config_path else find_default_config_path()

    raw_data: Dict[str, Any] = {}
    if resolved_path.exists():
        with open(resolved_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                raw_data = loaded

    # Apply environment variable overrides (e.g. TSUKIKO_AI__MODEL_PATH, TSUKIKO_APP__LOG_LEVEL)
    for env_key, env_val in os.environ.items():
        if env_key.startswith("TSUKIKO_"):
            parts = env_key[len("TSUKIKO_"):].lower().split("__")
            if len(parts) == 2:
                section, key = parts
                if section not in raw_data or not isinstance(raw_data[section], dict):
                    raw_data[section] = {}
                raw_data[section][key] = _parse_env_value(env_val)

    config = TsukikoConfig.model_validate(raw_data)
    _CONFIG_INSTANCE = config
    return config


def reset_config() -> None:
    """Clears the cached configuration singleton."""
    global _CONFIG_INSTANCE
    _CONFIG_INSTANCE = None


def get_config() -> TsukikoConfig:
    """Returns currently loaded configuration or initializes default."""
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        _CONFIG_INSTANCE = load_config()
    return _CONFIG_INSTANCE
