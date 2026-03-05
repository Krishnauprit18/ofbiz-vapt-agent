# OFBiz VAPT Agent

An AI-powered security agent for vulnerability assessment and penetration testing of Apache OFBiz.

## Usage

### Providing Vulnerability Input

You can provide a vulnerability description as a string:
```bash
python3 cli/analyze.py "Apache OFBiz SSTI to RCE in /catalog/control/viewImage..."
```

### Deployment Modes

By default, the agent uses Docker to deploy the target OFBiz instance. If you are running in an environment without Docker (like Google Colab) or want to use an already running OFBiz instance, use the `--no-docker` flag:

```bash
python3 cli/analyze.py --no-docker "Apache OFBiz SSTI to RCE in /catalog/control/viewImage..."
```
