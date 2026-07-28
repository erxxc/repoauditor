class Controls {
  void unsafePreview(HttpServletRequest request) throws Exception {
    new URL(request.getParameter("url")).openStream();
  }

  void safePreview(HttpServletRequest request) throws Exception {
    new URL("https://status.example.test/health").openStream();
  }
}
