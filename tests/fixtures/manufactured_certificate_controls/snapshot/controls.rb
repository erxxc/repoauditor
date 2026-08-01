def direct_marshaled
  Marshal.load(params[:user])
end

def base64_marshaled
  Marshal.load(Base64.decode64(params[:user]))
end

def constant_marshaled
  Marshal.load("fixed-payload")
end

def aliased_loader
  loader.load(params[:user])
end

def other_parser
  JSON.parse(params[:user])
end
