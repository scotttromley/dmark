# Releasing `dmark` To PyPI

## One-Time Setup

1. Create the project on PyPI:
   - `https://pypi.org/manage/project/dmark/`
2. Configure trusted publishing in PyPI:
   - Owner: `scotttromley`
   - Repository: `dmark`
   - Workflow: `.github/workflows/publish-pypi.yml`
   - Environment: `pypi`
3. In GitHub, create environment `pypi` for this repo.

## Release Steps

1. Update version in `pyproject.toml`.
2. Run local validation:
   - `python -m unittest discover -s tests -v`
   - `python -m build`
   - `python -m twine check dist/*`
3. Commit and push changes:
   - `git add -A`
   - `git commit -m "Release vX.Y.Z"`
   - `git push`
4. Tag the release and push the tag:
   - `git tag vX.Y.Z`
   - `git push origin vX.Y.Z`

The GitHub workflow will build and publish to PyPI automatically.

