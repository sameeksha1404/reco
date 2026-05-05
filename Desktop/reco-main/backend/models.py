from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from pydantic import BaseModel, Field

from db import Base


class ThreatRecord(Base):
    __tablename__ = "threats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False)
    weight: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)


class ControlRecord(Base):
    __tablename__ = "controls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(150), nullable=False)
    effectiveness: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)


class ThreatControlMap(Base):
    __tablename__ = "threat_control_map"

    threat_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("threats.id", ondelete="CASCADE"), primary_key=True
    )
    control_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("controls.id", ondelete="CASCADE"), primary_key=True
    )
    mapping_impact: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)
    effectiveness: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)
    control_name: Mapped[str] = mapped_column(String(150), nullable=False)


class SavedThreatControlSelection(Base):
    __tablename__ = "saved_threat_control_selections"
    __table_args__ = (UniqueConstraint("threat_id", "control_id", name="uq_saved_threat_control_pair"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(Integer, nullable=False)
    threat_name: Mapped[str] = mapped_column(String(150), nullable=False)
    control_id: Mapped[int] = mapped_column(Integer, nullable=False)
    control_name: Mapped[str] = mapped_column(String(150), nullable=False)
    impact: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    probability: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    risk_score: Mapped[float] = mapped_column(Numeric(6, 4), nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)
    updated_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class ThreatOut(BaseModel):
    id: int
    name: str
    category: str
    weight: float


class ControlOption(BaseModel):
    id: int
    name: str
    effectiveness: float
    impact: float
    score: float


class SelectionItem(BaseModel):
    threat_id: int = Field(..., gt=0)
    control_id: int = Field(..., gt=0)


class FinalRiskRequest(BaseModel):
    selections: list[SelectionItem]


class FinalRiskResponse(BaseModel):
    risk_score: float
    risk_level: str