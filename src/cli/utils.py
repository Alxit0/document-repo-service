from functools import wraps
import json
import logging
import os
import sys

import click

logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global state dictionary
state = None

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    os.makedirs(state_dir, exist_ok=True)

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)
    
    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state

def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug(f"Setting REP_ADDRESS from Environment to: {state["REP_ADDRESS"]}")

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    return state

def parse_args(state, key, repo, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if key:
        if not os.path.exists(key) or not os.path.isfile(key):
            logger.error(f"Key file not found or invalid: {key}")
            sys.exit(-1)
        
        with open(key, 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if repo:
        state['REP_ADDRESS'] = repo
        logger.info('Overriding REP_ADDRESS from command line')
    
    return state

def save(state):
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
        logger.debug('Creating state folder')
        os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))

    logger.info('State saved successfully.')
    logger.debug(state)


def default_command(func):
    @click.command()
    @click.option('-k', '--key', type=click.Path(exists=True, dir_okay=False), help="Path to the key file")
    @click.option('-r', '--repo', help="Address:Port of the repository")
    @click.option('-v', '--verbose', is_flag=True, help="Increase verbosity")
    @click.help_option('-h', '--help')
    @wraps(func)
    def wrapper(key, repo, verbose, *args, **kwargs):
        global state

        # Load initial state
        state = load_state()
        state = parse_env(state)
        state = parse_args(state, key, repo, verbose)
        
        # Call the original function
        resp = func(*args, **kwargs)

        save(state)
        return resp
            
    return wrapper
