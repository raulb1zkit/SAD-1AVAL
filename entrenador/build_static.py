#!/usr/bin/env python3
"""Exporta el banco del entrenador local para la versión estática de GitHub Pages."""
import argparse
import json
from pathlib import Path

import app

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
args = parser.parse_args()

questions = [
    {
        "id": index,
        "category": category,
        "text": text,
        "options": options,
        "answer": answer,
        "explanation": explanation,
    }
    for index, (category, text, options, answer, explanation) in enumerate(app.QUESTIONS)
]
Path(args.output).write_text(json.dumps(questions, ensure_ascii=False))
