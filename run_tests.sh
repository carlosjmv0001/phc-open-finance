#!/bin/bash  
  
# Check if docker-compose is running  
if ! docker-compose ps | grep -q "Up"; then  
    echo "Starting docker-compose..."  
    docker-compose up -d  
    sleep 15  
fi  
  
# Run unit tests  
echo "Running unit tests..."  
pytest tests/ -m unit -v  
  
# Run integration tests  
echo "Running integration tests..."  
pytest tests/ -m integration -v  
  
# Run revocation tests  
echo "Running revocation tests..."  
pytest tests/ -m revocation -v  
  
# Run verification tests  
echo "Running verification tests..."  
pytest tests/ -m verification -v  
  
# Run error tests  
echo "Running error tests..."  
pytest tests/ -m error -v  
  
# Run BDD tests  
echo "Running end-to-end tests..."  
behave tests/features/  
  
# Generate coverage report  
echo "Generating coverage report..."  
pytest tests/ --cov=src --cov-report=html