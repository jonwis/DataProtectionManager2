#include "pch.h"
#include "DataProtectionProvider.h"

DecryptionReadStream::DecryptionReadStream(IStream* encryptedSource) : m_source(encryptedSource)
{
    m_streamInfo.pvCallbackCtxt = this;
    m_streamInfo.pfnStreamOutput = [](void* context, BYTE const* data, SIZE_T size, BOOL) -> SECURITY_STATUS
        {
            auto self = static_cast<DecryptionReadStream*>(context);
            self->m_pendingData.insert(self->m_pendingData.end(), data, data + size);
            return 0;
        };

    THROW_IF_WIN32_ERROR(::NCryptStreamOpenToUnprotect(&m_streamInfo, 0, nullptr, &m_streamHandle));
}

DecryptionReadStream::~DecryptionReadStream()
{
    ::NCryptStreamClose(m_streamHandle);
}

STDMETHODIMP DecryptionReadStream::Read(void* pv, ULONG size, ULONG* read) noexcept try
{
    EnsureAvailableBytes(size);

    auto toRead = (std::min)(static_cast<size_t>(size), m_pendingData.size());
    std::uninitialized_copy_n(m_pendingData.data(), toRead, static_cast<uint8_t*>(pv));
    m_pendingData.erase(m_pendingData.begin(), m_pendingData.begin() + toRead);
    wil::assign_to_opt_param(read, static_cast<ULONG>(toRead));

    return S_OK;
}
CATCH_RETURN();

void DecryptionReadStream::EnsureAvailableBytes(size_t desiredSize)
{
    if (m_finalBlockRead)
    {
        return;
    }

    while (m_pendingData.size() < desiredSize)
    {
        // Read a block from m_source, then write it to m_transmute, which will
        // call us back with bytes we can append to m_pendingData. If the read
        // size is zero, then we're done and this is the last chunk to process.
        auto readSize = wil::stream_read_partial(m_source.get(), m_sourceReadBuffer.data(), static_cast<unsigned long>(m_sourceReadBuffer.size()));
        if (readSize == 0)
        {
            m_finalBlockRead = true;
            break;
        }

        // Pass the chunk through the transmute stream, which calls us back with write
        THROW_IF_WIN32_ERROR(::NCryptStreamUpdate(m_streamHandle, m_sourceReadBuffer.data(), readSize, FALSE));
    }

    if (m_finalBlockRead)
    {
        THROW_IF_WIN32_ERROR(::NCryptStreamUpdate(m_streamHandle, nullptr, 0, TRUE));
    }
}


STDMETHODIMP DecryptionReadStream::Write(void const*, ULONG, ULONG* pcbWritten) noexcept
{
    wil::assign_to_opt_param(pcbWritten, 0ul);
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::Commit(ULONG) noexcept
{
    return S_OK;
}

STDMETHODIMP DecryptionReadStream::Revert() noexcept
{
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::Seek(LARGE_INTEGER, DWORD, ULARGE_INTEGER* newPos) noexcept
{
    wil::assign_to_opt_param(newPos, {});
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::SetSize(ULARGE_INTEGER) noexcept
{
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::CopyTo(::IStream*, ULARGE_INTEGER, ULARGE_INTEGER* read, ULARGE_INTEGER* written) noexcept
{
    wil::assign_to_opt_param(read, {});
    wil::assign_to_opt_param(written, {});
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::Clone(IStream** result) noexcept
{
    wil::assign_null_to_opt_param(result);
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::Stat(STATSTG* stats, DWORD) noexcept
{
    *stats = {};
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept
{
    return E_NOTIMPL;
}

STDMETHODIMP DecryptionReadStream::UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) noexcept
{
    return E_NOTIMPL;
}
