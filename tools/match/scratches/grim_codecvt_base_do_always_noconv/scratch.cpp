namespace std {

class codecvt_base {
protected:
    virtual bool do_always_noconv(void) const;
};

bool codecvt_base::do_always_noconv(void) const
{
    return true;
}

}
