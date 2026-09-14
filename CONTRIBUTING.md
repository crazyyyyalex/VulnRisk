# Contributing to VulnRisk

Thank you for your interest in contributing to VulnRisk! This document provides guidelines for contributing to our open-source vulnerability risk assessment platform.

## 🚀 **Quick Start for Contributors**

### **Prerequisites**
- Docker & Docker Compose
- Python 3.13+ and [uv](https://docs.astral.sh/uv/) (optional, for backend-only local work)
- Git
- Basic understanding of vulnerability management

### **Development Setup**
```bash
# Fork and clone the repository
git clone https://github.com/GurkhaShieldForce/vulnrisk-public.git
cd vulnrisk-public

# Set up development environment (Docker)
./setup.sh

# Verify setup
curl http://localhost:8000/health
```

### **Backend-only local setup (optional)**
```bash
cd backend
uv sync --all-groups
make dev
```

## 🎯 **How to Contribute**

### **1. Report Issues**
- Use GitHub Issues to report bugs
- Include steps to reproduce
- Provide environment details
- Use appropriate labels

### **2. Suggest Features**
- Use GitHub Issues for feature requests
- Describe the problem you're solving
- Provide use cases and examples
- Tag with `enhancement` label

### **3. Submit Code**
- Fork the repository
- Create a feature branch
- Make your changes
- Add tests
- Submit a pull request

## 📝 **Development Guidelines**

### **Code Style**
- Follow PEP 8 for Python code
- Use TypeScript for frontend code
- Add docstrings for functions
- Include type hints

### **Testing**
- Add tests for new functionality
- Ensure all tests pass
- Test both success and error cases
- Update existing tests if needed

### **Documentation**
- Update README if needed
- Add docstrings for new functions
- Update API documentation
- Include examples in comments

## 🏷️ **Issue Labels**

- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Improvements to documentation
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention is needed
- `question` - Further information is requested

## 🔄 **Pull Request Process**

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Add** tests for new functionality
5. **Ensure** all tests pass (`python -m pytest`)
6. **Commit** your changes (`git commit -m 'feat: add amazing feature'`)
7. **Push** to the branch (`git push origin feature/amazing-feature`)
8. **Open** a Pull Request

## 🎯 **Good First Issues**

Looking for your first contribution? Check out these issues:

- [ ] Add support for [Scanner Name] integration
- [ ] Improve error messages in risk calculation
- [ ] Add unit tests for [Component Name]
- [ ] Update documentation for [Feature Name]
- [ ] Fix typo in [File Name]

## 🏆 **Recognition**

We recognize contributors in several ways:

- **Contributor of the Month** - Featured in our newsletter
- **First-time Contributor** - Special badge and recognition
- **Community Spotlight** - Featured on our blog
- **Contributor Hall of Fame** - Permanent recognition

## 📞 **Getting Help**

- **GitHub Discussions** - Ask questions and get help
- **Documentation** - Check our comprehensive docs

## 📄 **Code of Conduct**

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🎉 **Thank You**

Thank you for contributing to VulnRisk! Your contributions help make vulnerability management more transparent and accessible to all security teams.
