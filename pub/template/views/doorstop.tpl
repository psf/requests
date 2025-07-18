%setdefault('has_index', True)
%setdefault('has_matrix', True)
% rebase('base.tpl', stylesheet='doorstop.css')
<header class="navbar navbar-expand-lg navbar-dark bd-navbar sticky-top text-bg-secondary">
  <nav class="container-xxl bd-gutter flex-wrap flex-lg-nowrap" aria-label="Document attributes">
    <div class="container-fluid">
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNavDropdown" aria-controls="navbarNavDropdown" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarNavDropdown">
        <ul class="navbar-nav">
          % if is_doc:
          %   tmpRef='../'
          % else:
          %   tmpRef=''
          % end
          % if has_index:
          <li class="nav-item">
            <a class="nav-link" href="{{ tmpRef }}index.html">Documents</a>
          </li>
          % end
          % if has_matrix:
          <li class="nav-item">
            <a class="nav-link" href="{{ tmpRef }}traceability.html">Traceability</a>
          </li>
          % end
          % if toc:
          <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              Contents
            </a>
            <ul class="dropdown-menu">
              % old_depth = 0
              % for item in toc:
              %   if item['depth'] > old_depth:
                <ul>
              %   elif item['depth'] < old_depth:
                </ul>
              %   end
                <li><a class="dropdown-item" href="#{{item['uid']}}">{{item['text']}}</a></li>
              %   old_depth = item['depth']
              % end
            </ul>
          </li>
          % end
        </ul>
      </div>
    </div>
    <div class="container-fluid">
      <div class="row">
        <div class="col-2">
          <div class="bd-lead text-nowrap">
            <!-- Insert logotype. -->
            <img src="{{baseurl}}{{tmpRef}}template/logo-black-white.png" alt="Doorstop" height="128" class="d-inline-block align-text-top">
          </div>
        </div>
        <div class="col-6 align-self-center">
          <div class="bd-lead text-nowrap text-center">
            <span class="text-monospace"><strong>{{doc_attributes["name"]}}</strong></span>
          </div>
        </div>
        <div class="col-2">
          <div class="bd-lead text-nowrap">
            <span class="text-muted">Ref</span>
            <p><span class="text-monospace">{{doc_attributes["ref"]}}</span></p>
          </div>
        </div>
        <div class="col-2">
          <div class="bd-lead text-nowrap">
            <span class="text-muted">By</span>
            <p><span class="text-monospace">{{doc_attributes["by"]}}</span></p>
            <span class="text-muted">Issue</span>
            <p><span class="text-monospace">{{doc_attributes["major"]}}{{doc_attributes["minor"]}}</span></p>
          </div>
        </div>
      </div>
    </div>
    </div>
  </nav>
</header>
<div class="container-xxl bd-gutter mt-3 my-md-4 bd-layout">
  <main class="bd-main order-1">
    <div class="bd-intro ps-lg-4">
      <H1>{{!doc_attributes["title"]}}</H1>
      {{!body}}
    </div>
  </main>
</div>
<script src="{{baseurl}}{{tmpRef}}template/bootstrap.bundle.min.js"></script>