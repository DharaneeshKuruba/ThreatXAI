#!/usr/bin/env bash
# run.sh — ThreatXAI quick-start script
# Usage: bash run.sh [--train]

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV="$ROOT/.venv"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
ML="$ROOT/ml"

# ─── Colors ───────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗"
echo "     ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝"
echo "     ██║   ███████║██████╔╝█████╗  ███████║   ██║   "
echo "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   "
echo "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   "
echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝  "
echo -e "  ${NC}${BOLD}XAI-IDS | SHAP + LIME + EDAC${NC}"
echo ""

# Step 1: Python venv
if [ ! -d "$VENV" ]; then
  echo -e "${YELLOW}► Creating Python virtual environment...${NC}"
  python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"

# Step 2: Install Python deps
echo -e "${YELLOW}► Installing Python dependencies...${NC}"
pip install -q -r "$ROOT/requirements.txt"
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Step 3: ML Pipeline (optional --train flag)
if [[ "$1" == "--train" ]]; then
  echo -e "${YELLOW}► Running ML pipeline...${NC}"
  cd "$ML"
  python preprocess.py
  python train.py
  python evaluate.py
  python edac.py
  echo -e "${GREEN}✓ ML pipeline complete${NC}"
  cd "$ROOT"
fi

# Step 4: Check if models exist
if [ ! -f "$ML/models/xgboost_model.pkl" ]; then
  echo -e "${RED}⚠ No trained models found. Run: bash run.sh --train${NC}"
  echo -e "${YELLOW}  Starting server in DEMO mode (sample data)...${NC}"
fi

# Step 5: Frontend dependencies
if [ ! -d "$FRONTEND/node_modules" ]; then
  echo -e "${YELLOW}► Installing npm dependencies...${NC}"
  cd "$FRONTEND" && npm install --silent && cd "$ROOT"
fi

# Step 6: Start backend & frontend concurrently
echo ""
echo -e "${GREEN}${BOLD}★ Starting ThreatXAI...${NC}"
echo -e "${CYAN}  Backend:  http://localhost:8000${NC}"
echo -e "${CYAN}  Frontend: http://localhost:5173${NC}"
echo -e "${CYAN}  API Docs: http://localhost:8000/docs${NC}"
echo ""

# Start backend
cd "$BACKEND"
uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
echo -e "${GREEN}✓ Backend started (PID $BACKEND_PID)${NC}"

sleep 2

# Start frontend
cd "$FRONTEND"
npm run dev &
FRONTEND_PID=$!
echo -e "${GREEN}✓ Frontend started (PID $FRONTEND_PID)${NC}"

echo ""
echo -e "${BOLD}Press Ctrl+C to stop all services${NC}"

# Cleanup on exit
trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; echo 'Services stopped.'" EXIT SIGINT SIGTERM
wait
