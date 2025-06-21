#!/bin/bash
cd /home/kavia/workspace/code-generation/recipehub-28906-feff5cc0/recipe_frontend_workspace/recipe_frontend
npm run lint
ESLINT_EXIT_CODE=$?
npm run build
BUILD_EXIT_CODE=$?
if [ $ESLINT_EXIT_CODE -ne 0 ] || [ $BUILD_EXIT_CODE -ne 0 ]; then
   exit 1
fi

