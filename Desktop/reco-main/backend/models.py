from sqlalchemy import ForeignKey, Integer, Numeric, String
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
        Integer, ForeignKey("threats.id", on_delete="CASCADE"), primary_key=True
    )
    control_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("controls.id", on_delete="CASCADE"), primary_key=True
    )
    mapping_impact: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)
    effectiveness: Mapped[float] = mapped_column(Numeric(4, 2), nullable=False)
    control_name: Mapped[str] = mapped_column(String(150), nullable=False)


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