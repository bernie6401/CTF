export default function postFilter() {
  return async (req, res, next) => {
    // Patch: Block session eval
    if (
      JSON.stringify(req.session ?? '')
        .toLowerCase()
        .includes('eval')
    ) {
      res.status(400).send('Bad request')
      res.end()
      return
    } else if (
      JSON.stringify(req.cookies ?? '')
        .toLowerCase()
        .includes('eval')
    ) {
      res.status(400).send('Bad request')
      res.end()
      return
    } else if (
      JSON.stringify(req.headers['cookie'] ?? '')
        .toLowerCase()
        .includes('eval')
    ) {
      res.status(400).send('Bad request')
      res.end()
      return
    }
    // End patch
    else next()
  }
}
